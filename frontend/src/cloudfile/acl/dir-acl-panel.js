import React from 'react';
import { Button, Form, FormGroup, Input, Label, Table } from 'reactstrap';
import PropTypes from 'prop-types';
import { v4 as uuidv4 } from 'uuid';
import Loading from '@/components/loading';
import toaster from '@/components/toast';
import { gettext } from '@/utils/constants';
import { cloudFileAPI } from '../cloudfile-api';

const TYPES = [['user', gettext('User')], ['dept', gettext('Department')], ['group', gettext('Group')]];
const PERMISSIONS = [['invisible', gettext('Invisible')], ['none', gettext('No access')],
  ['r', gettext('Read only')], ['rw', gettext('Read write')]];

class DirACLPanel extends React.Component {
  state = { loading: true, busy: false, failed: false, rules: [], shares: [], cursors: {}, provider: '',
    domain: 'rules', subjectType: 'user', subject: '', namespace: '', permission: 'r', inherit: true, editing: null };
  pendingKeys = new Map();
  generation = 0;
  mounted = false;
  inFlight = false;
  componentDidMount() { this.mounted = true; this.load(); }
  componentDidUpdate(previous) {
    if (previous.repoID !== this.props.repoID || previous.path !== this.props.path) this.load();
  }
  componentWillUnmount() { this.mounted = false; this.generation++; }
  reference = () => ({ repo_id: this.props.repoID, path: this.props.path, kind: 'dir' });
  errorMessage = error => error.response?.data?.message || gettext('Error');
  load = async () => {
    const generation = ++this.generation;
    // A stale pagination request must not leave the newly selected folder busy.
    this.setState({ loading: true, busy: this.inFlight, failed: false, domain: 'rules', editing: null });
    try {
      const domains = this.props.path === '/' ? ['rules'] : ['rules', 'shares'];
      const responses = await Promise.all(domains.map(domain => cloudFileAPI.listDirectoryPolicy(this.props.repoID, this.props.path, domain)));
      if (generation !== this.generation) return;
      const next = { rules: [], shares: [], cursors: {}, loading: false, provider: responses[0].data.subject_provider };
      responses.forEach((response, i) => { next[domains[i]] = response.data.items; next.cursors[domains[i]] = response.data.next_after; });
      this.setState(next);
    } catch (error) {
      if (generation !== this.generation) return;
      this.setState({ loading: false, failed: true });
      toaster.danger(this.errorMessage(error));
    }
  };
  more = async domain => {
    const generation = this.generation;
    this.setState({ busy: true });
    try {
      const response = await cloudFileAPI.listDirectoryPolicy(this.props.repoID, this.props.path, domain, this.state.cursors[domain]);
      if (generation === this.generation) this.setState(state => ({
        [domain]: [...state[domain], ...response.data.items.filter(item => !state[domain].some(old => old.id === item.id))],
        cursors: { ...state.cursors, [domain]: response.data.next_after },
      }));
    } catch (error) { toaster.danger(this.errorMessage(error)); }
    finally { if (generation === this.generation) this.setState({ busy: false }); }
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
    const { provider, subjectType, subject, namespace, domain, permission, inherit, editing } = this.state;
    const value = { path: this.props.path,
      subject: { type: subjectType, provider, namespace: subjectType === 'user' ? 'user' : namespace.trim(), external_id: subject.trim() },
      ...(domain === 'rules' ? { kind: 'dir', permission, inherit } : {}) };
    const reference = this.reference();
    if (editing && domain === 'rules') {
      this.mutate({ action: 'replace', reference, value, id: editing.id, etag: editing.etag },
        key => cloudFileAPI.replaceDirectoryRule(reference, value, editing, key));
      return;
    }
    this.mutate({ action: 'create', domain, reference, value }, key => cloudFileAPI.createDirectoryPolicy(reference, value, domain, key));
  };
  remove = (domain, rule) => {
    const reference = this.reference();
    this.mutate({ action: 'delete', domain, reference, id: rule.id, etag: rule.etag },
      key => cloudFileAPI.deleteDirectoryPolicy(reference, rule, domain, key));
  };
  renderTable = domain => (
    <React.Fragment>
      <Table><thead><tr><th>{gettext('Type')}</th><th>{gettext('Subject')}</th><th>{gettext('Permission')}</th><th>{gettext('Inherit')}</th><th></th></tr></thead>
        <tbody>
          {this.state[domain].length === 0 && <tr><td colSpan="5">{gettext('No rules on this folder.')}</td></tr>}
          {this.state[domain].map(rule => (
            <tr key={rule.id}>
              <td>{TYPES.find(([type]) => type === rule.subject.type)?.[1]}</td>
              <td>{rule.subject.external_id}{rule.subject.type !== 'user' && ` (${rule.subject.namespace})`}</td>
              <td>{domain === 'shares' ? gettext('Read only by default') : PERMISSIONS.find(([permission]) => permission === rule.permission)?.[1]}</td>
              <td>{domain === 'shares' || rule.inherit ? gettext('Yes') : gettext('No')}</td>
              <td>
                {domain === 'rules' && (
                  <Button color="link" disabled={this.state.busy} onClick={() => this.setState({
                    editing: rule, domain, subjectType: rule.subject.type, subject: rule.subject.external_id,
                    namespace: rule.subject.namespace, permission: rule.permission, inherit: rule.inherit,
                  })}>{gettext('Edit')}
                  </Button>)}
                <Button color="link" disabled={this.state.busy} onClick={() => this.remove(domain, rule)}>{gettext('Delete')}</Button>
              </td>
            </tr>))}
        </tbody>
      </Table>
      {this.state.cursors[domain] && <Button disabled={this.state.busy} onClick={() => this.more(domain)}>{gettext('Load more')}</Button>}
    </React.Fragment>
  );
  render() {
    const { loading, busy, failed, domain, subjectType, subject, namespace, permission, inherit, provider, editing } = this.state;
    if (loading) return <Loading />;
    if (failed) return <Button onClick={this.load}>{gettext('Retry')}</Button>;
    return (
      <div className="cloudfile-dir-acl">
        <h4>{gettext('Directory permissions')}: {this.props.path}</h4>
        <p className="text-secondary">{gettext('Directory rules also apply to users without library access. Inherited rules apply to child folders.')}</p>
        {this.renderTable('rules')}
        {this.props.path !== '/' && (
          <React.Fragment><h4>{gettext('Directory sharing')}</h4>
            <p className="text-secondary">{gettext('Sharing gives read access by default. Directory permissions determine write access and restrictions. Removing a share keeps directory rules.')}</p>
            {this.renderTable('shares')}
          </React.Fragment>)}
        <Form onSubmit={this.submit}>
          <FormGroup><Label for="cf-policy-domain">{gettext('Add')}</Label>
            <Input id="cf-policy-domain" type="select" value={domain} onChange={e => this.setState({ domain: e.target.value, editing: null })}>
              <option value="rules">{gettext('Directory permissions')}</option>
              {this.props.path !== '/' && <option value="shares">{gettext('Directory sharing')}</option>}
            </Input>
          </FormGroup>
          <FormGroup><Label for="cf-policy-type">{gettext('Type')}</Label>
            <Input id="cf-policy-type" type="select" value={subjectType} onChange={e => this.setState({ subjectType: e.target.value, namespace: '' })}>
              {TYPES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </Input>
          </FormGroup>
          {subjectType !== 'user' && (
            <FormGroup><Label for="cf-policy-namespace">{gettext('Directory namespace')}</Label>
              <Input id="cf-policy-namespace" required value={namespace} onChange={e => this.setState({ namespace: e.target.value })} />
            </FormGroup>)}
          <FormGroup><Label for="cf-policy-subject">{gettext('Subject ID')}</Label>
            <Input id="cf-policy-subject" required value={subject} onChange={e => this.setState({ subject: e.target.value })} />
          </FormGroup>
          {domain === 'rules' && (
            <React.Fragment>
              <FormGroup><Label for="cf-policy-permission">{gettext('Permission')}</Label>
                <Input id="cf-policy-permission" type="select" value={permission} onChange={e => this.setState({ permission: e.target.value })}>
                  {PERMISSIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </Input>
              </FormGroup>
              <FormGroup check><Label check><Input type="checkbox" checked={inherit} onChange={e => this.setState({ inherit: e.target.checked })} />{gettext('Inherit')}</Label></FormGroup>
            </React.Fragment>)}
          <Button type="submit" color="primary" disabled={busy || !provider || !subject.trim() || (subjectType !== 'user' && !namespace.trim())}>{editing ? gettext('Save') : gettext('Add')}</Button>
          {editing && <Button disabled={busy} onClick={() => this.setState({ editing: null })}>{gettext('Cancel')}</Button>}
        </Form>
      </div>
    );
  }
}
DirACLPanel.propTypes = { repoID: PropTypes.string.isRequired, path: PropTypes.string.isRequired };
export default DirACLPanel;
