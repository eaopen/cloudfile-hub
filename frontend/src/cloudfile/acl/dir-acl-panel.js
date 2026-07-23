import React from 'react';
import PropTypes from 'prop-types';
import { Button, Form, FormGroup, Input, Label, Table } from 'reactstrap';
import { gettext } from '../../utils/constants';
import toaster from '../../components/toast';
import Loading from '../../components/loading';
import { cloudFileAPI } from '../cloudfile-api';

const SUBJECT_TYPES = [
  { value: 'user', label: gettext('User') },
  { value: 'dept', label: gettext('Department') },
  { value: 'group', label: gettext('Group') },
];

// Ordered strictest first, matching the lattice in acl-semantics.md.
const PERMISSIONS = [
  { value: 'invisible', label: gettext('Invisible') },
  { value: 'none', label: gettext('No access') },
  { value: 'r', label: gettext('Read only') },
  { value: 'rw', label: gettext('Read write') },
];

class DirACLPanel extends React.Component {

  constructor(props) {
    super(props);
    this.state = {
      isLoading: true,
      rules: [],
      subjectType: 'user',
      subject: '',
      permission: 'r',
      inherit: true,
    };
  }

  componentDidMount() {
    this.loadRules();
  }

  loadRules = () => {
    const { repoID, path } = this.props;
    this.setState({ isLoading: true });
    cloudFileAPI.listDirACL(repoID, path).then((res) => {
      this.setState({ isLoading: false, rules: res.data.rules });
    }).catch((error) => {
      this.setState({ isLoading: false });
      toaster.danger(this.errorMessage(error));
    });
  };

  errorMessage = (error) => {
    if (error.response && error.response.data && error.response.data.error_msg) {
      return error.response.data.error_msg;
    }
    return gettext('Error');
  };

  onSubmit = (event) => {
    event.preventDefault();
    const { repoID, path } = this.props;
    const { subjectType, subject, permission, inherit } = this.state;
    if (!subject.trim()) {
      toaster.danger(gettext('Please enter a user, department or group.'));
      return;
    }
    cloudFileAPI.setDirACL(repoID, path, subjectType, subject.trim(), permission, inherit)
      .then(() => {
        this.setState({ subject: '' });
        this.loadRules();
      }).catch((error) => {
        toaster.danger(this.errorMessage(error));
      });
  };

  onDelete = (rule) => {
    const { repoID, path } = this.props;
    cloudFileAPI.deleteDirACL(repoID, path, rule.subject_type, rule.subject)
      .then(() => {
        this.loadRules();
      }).catch((error) => {
        toaster.danger(this.errorMessage(error));
      });
  };

  render() {
    const { path } = this.props;
    const { isLoading, rules, subjectType, subject, permission, inherit } = this.state;

    return (
      <div className="cloudfile-dir-acl">
        <h4>{gettext('Directory permissions')}: {path}</h4>
        <p className="text-secondary">
          {gettext('Rules apply to this folder and, unless inheritance is turned off, to everything below it. A rule can only narrow the permission a user already has, never widen it.')}
        </p>

        {isLoading ? <Loading /> : (
          <Table>
            <thead>
              <tr>
                <th>{gettext('Type')}</th>
                <th>{gettext('Subject')}</th>
                <th>{gettext('Permission')}</th>
                <th>{gettext('Inherit')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rules.length === 0 && (
                <tr><td colSpan="5">{gettext('No rules on this folder.')}</td></tr>
              )}
              {rules.map((rule) => (
                <tr key={`${rule.subject_type}:${rule.subject}`}>
                  <td>{rule.subject_type}</td>
                  <td>{rule.subject}</td>
                  <td>{rule.permission}</td>
                  <td>{rule.inherit ? gettext('Yes') : gettext('No')}</td>
                  <td>
                    <Button color="link" onClick={() => this.onDelete(rule)}>
                      {gettext('Delete')}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}

        <Form inline onSubmit={this.onSubmit}>
          <FormGroup className="mr-2">
            <Input type="select" value={subjectType}
              onChange={(e) => this.setState({ subjectType: e.target.value })}>
              {SUBJECT_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </Input>
          </FormGroup>
          <FormGroup className="mr-2">
            <Input type="text" value={subject} placeholder={gettext('Email or group id')}
              onChange={(e) => this.setState({ subject: e.target.value })} />
          </FormGroup>
          <FormGroup className="mr-2">
            <Input type="select" value={permission}
              onChange={(e) => this.setState({ permission: e.target.value })}>
              {PERMISSIONS.map((p) => (
                <option key={p.value} value={p.value}>{p.label}</option>
              ))}
            </Input>
          </FormGroup>
          <FormGroup check className="mr-2">
            <Label check>
              <Input type="checkbox" checked={inherit}
                onChange={(e) => this.setState({ inherit: e.target.checked })} />
              {gettext('Inherit')}
            </Label>
          </FormGroup>
          <Button type="submit" color="primary">{gettext('Add')}</Button>
        </Form>
      </div>
    );
  }
}

DirACLPanel.propTypes = {
  repoID: PropTypes.string.isRequired,
  path: PropTypes.string.isRequired,
};

export default DirACLPanel;
