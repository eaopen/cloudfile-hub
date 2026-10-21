import React from 'react';
import { Button, Form, FormGroup, Input, Label, Table } from 'reactstrap';
import PropTypes from 'prop-types';
import { v4 as uuidv4 } from 'uuid';
import { cloudFileAPI } from '@/cloudfile/cloudfile-api';
import Loading from '@/components/loading';
import toaster from '@/components/toast';
import { gettext } from '@/utils/constants';

const TYPES = [['user', gettext('User')], ['org', gettext('Department')], ['role', gettext('Role')]];
const PERMISSIONS = [['invisible', gettext('Invisible')],
  ['r', gettext('Read only')], ['rw', gettext('Read write')]];

class DirACLPanel extends React.Component {
  state = { loading: true, busy: false, failed: false, rules: [],
    domain: 'rules', subjectType: 'user', subject: '', namespace: '', permission: 'r', inherit: true, shareMode: false, editing: null };
  pendingKeys = new Map();
  generation = 0;
  mounted = false;
  inFlight = false;
  componentDidMount() { this.mounted = true; this.load(); }
  componentDidUpdate(previous) {
    if (previous.repoID !== this.props.repoID || previous.path !== this.props.path) this.load();
  }
  componentWillUnmount() { this.mounted = false; this.generation++; }
  errorMessage = error => error.response?.data?.message || gettext('Error');
  load = async () => {
    const generation = ++this.generation;
    // A stale directory request must not leave the newly selected folder busy.
    this.setState({ loading: true, busy: this.inFlight, failed: false, domain: 'rules', editing: null });
    try {
      const response = await cloudFileAPI.listDirectoryPolicy(this.props.repoID, this.props.path);
      if (generation !== this.generation) return;
      this.setState({ rules: response.data.data, loading: false });
    } catch (error) {
      if (generation !== this.generation) return;
      this.setState({ loading: false, failed: true });
      toaster.danger(this.errorMessage(error));
    }
  };
  mutate = async (payload, execute) => {
    if (this.inFlight || this.state.busy) return;
    this.inFlight = true;
    const signature = JSON.stringify(payload);
    if (!this.pendingKeys.has(signature)) this.pendingKeys.set(signature, uuidv4());
    this.setState({ busy: true });
    try {
      await execute(this.pendingKeys.get(signature));
      this.pendingKeys.delete(signature);
      if (this.mounted) await this.load();
    } catch (error) { toaster.danger(this.errorMessage(error)); }
    finally { this.inFlight = false; if (this.mounted) this.setState({ busy: false }); }
  };
  submit = event => {
    event.preventDefault();
    const { subjectType, subject, namespace, permission, inherit, shareMode, editing } = this.state;
    const rule = { repo_id: this.props.repoID, path: this.props.path,
      subject_type: subjectType, namespace: subjectType === 'user' ? 'user' : namespace.trim(),
      external_id: subject.trim(), permission, inherit,
      share_mode: this.props.path !== '/' && permission !== 'invisible' && shareMode,
      expected: editing ? editing.revision : null };
    this.mutate(rule, revision => cloudFileAPI.writeDirectoryRule({ ...rule, revision }));
  };
  remove = (domain, rule) => {
    const { repo_id, path, subject_type, namespace, external_id, permission, inherit, share_mode } = rule;
    const value = { repo_id, path, subject_type, namespace, external_id, permission, inherit, share_mode,
      expected: rule.revision };
    this.mutate({ action: 'delete', ...value }, revision => cloudFileAPI.writeDirectoryRule({ ...value, revision }, true));
  };
  renderTable = domain => (
    <React.Fragment>
      <Table><thead><tr><th>{gettext('Type')}</th><th>{gettext('Subject')}</th><th>{gettext('Permission')}</th><th>{gettext('Inherit')}</th><th>{gettext('Directory sharing')}</th><th></th></tr></thead>
        <tbody>
          {this.state[domain].length === 0 && <tr><td colSpan="6">{gettext('No rules on this folder.')}</td></tr>}
          {this.state[domain].map(rule => (
            <tr key={JSON.stringify([rule.subject_type, rule.namespace, rule.external_id])}>
              <td>{TYPES.find(([type]) => type === rule.subject_type)?.[1]}</td>
              <td>{rule.external_id}{rule.subject_type !== 'user' && ` (${rule.namespace})`}</td>
              <td>{PERMISSIONS.find(([permission]) => permission === rule.permission)?.[1]}</td>
              <td>{rule.inherit ? gettext('Yes') : gettext('No')}</td>
              <td>{rule.share_mode ? gettext('Yes') : gettext('No')}</td>
              <td>
                {domain === 'rules' && (
                  <Button color="link" disabled={this.state.busy} onClick={() => this.setState({
                    editing: rule, domain, subjectType: rule.subject_type, subject: rule.external_id,
                    namespace: rule.namespace, permission: rule.permission, inherit: rule.inherit, shareMode: rule.share_mode,
                  })}>{gettext('Edit')}
                  </Button>)}
                <Button color="link" disabled={this.state.busy} onClick={() => this.remove(domain, rule)}>{gettext('Delete')}</Button>
              </td>
            </tr>))}
        </tbody>
      </Table>
    </React.Fragment>
  );
  render() {
    const { loading, busy, failed, domain, subjectType, subject, namespace, permission, inherit, shareMode, editing } = this.state;
    if (loading) return <Loading />;
    if (failed) return <Button onClick={this.load}>{gettext('Retry')}</Button>;
    return (
      <div className="cloudfile-dir-acl">
        <h4>{gettext('Directory permissions')}: {this.props.path}</h4>
        <p className="text-secondary">{gettext('Enable sharing to allow access without library membership. Permissions and inheritance are controlled by the same rule.')}</p>
        {this.renderTable('rules')}
        <Form onSubmit={this.submit}>
          <FormGroup><Label for="cf-policy-type">{gettext('Type')}</Label>
            <Input id="cf-policy-type" disabled={!!editing} type="select" value={subjectType} onChange={e => this.setState({ subjectType: e.target.value, namespace: '' })}>
              {TYPES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </Input>
          </FormGroup>
          {subjectType !== 'user' && (
            <FormGroup><Label for="cf-policy-namespace">{gettext('Directory namespace')}</Label>
              <Input id="cf-policy-namespace" disabled={!!editing} required value={namespace} onChange={e => this.setState({ namespace: e.target.value })} />
            </FormGroup>)}
          <FormGroup><Label for="cf-policy-subject">{gettext('Subject ID')}</Label>
            <Input id="cf-policy-subject" disabled={!!editing} required value={subject} onChange={e => this.setState({ subject: e.target.value })} />
          </FormGroup>
          {domain === 'rules' && (
            <React.Fragment>
              <FormGroup><Label for="cf-policy-permission">{gettext('Permission')}</Label>
                <Input id="cf-policy-permission" type="select" value={permission} onChange={e => this.setState({ permission: e.target.value })}>
                  {PERMISSIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </Input>
              </FormGroup>
              <FormGroup check><Label check><Input type="checkbox" checked={inherit} onChange={e => this.setState({ inherit: e.target.checked })} />{gettext('Inherit')}</Label></FormGroup>
              {this.props.path !== '/' && (
                <FormGroup check>
                  <Label check>
                    <Input type="checkbox" checked={shareMode} onChange={e => this.setState({ shareMode: e.target.checked })} />
                    {gettext('Allow access without library membership')}
                  </Label>
                </FormGroup>
              )}
            </React.Fragment>)}
          <Button type="submit" color="primary" disabled={busy || !subject.trim() || (subjectType !== 'user' && !namespace.trim())}>{editing ? gettext('Save') : gettext('Add')}</Button>
          {editing && <Button disabled={busy} onClick={() => this.setState({ editing: null })}>{gettext('Cancel')}</Button>}
        </Form>
      </div>
    );
  }
}
DirACLPanel.propTypes = { repoID: PropTypes.string.isRequired, path: PropTypes.string.isRequired };
export default DirACLPanel;
