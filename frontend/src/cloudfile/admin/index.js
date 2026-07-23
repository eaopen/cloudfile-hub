import React from 'react';
import { createRoot } from 'react-dom/client';
import { Table } from 'reactstrap';
import { gettext } from '../../utils/constants';
import Loading from '../../components/loading';
import { loadFeatures } from '../features';

/*
 * CloudFile capability overview.
 *
 * The baseline's one frontend page. It exists for two reasons: operators need
 * to see which CF_ENABLE_* switches a deployment actually has on -- the
 * switches are set in .env and written into seahub_settings.py at container
 * start, so there is otherwise nowhere to read them back -- and it keeps the
 * frontend extension seam (webpack entry, API client, feature loading)
 * exercised by something real rather than by a placeholder.
 *
 * Capabilities add their own pages on their own branches; this one only
 * reports.
 */

function CapabilityTable({ features }) {
  const names = Object.keys(features);

  if (names.length === 0) {
    return (
      <p>
        {gettext('No CloudFile capabilities are enabled. This deployment behaves as native Seafile CE.')}
      </p>
    );
  }

  return (
    <Table>
      <thead>
        <tr>
          <th>{gettext('Capability')}</th>
          <th>{gettext('Status')}</th>
        </tr>
      </thead>
      <tbody>
        {names.map((name) => (
          <tr key={name}>
            <td><code>{name}</code></td>
            <td>{features[name] ? gettext('Enabled') : gettext('Disabled')}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

class CloudFileAdmin extends React.Component {

  constructor(props) {
    super(props);
    this.state = { isLoading: true, features: {} };
  }

  componentDidMount() {
    loadFeatures().then((features) => {
      this.setState({ isLoading: false, features });
    });
  }

  render() {
    const { isLoading, features } = this.state;
    return (
      <div className="cloudfile-admin">
        <h4>{gettext('CloudFile capabilities')}</h4>
        {isLoading ? <Loading /> : <CapabilityTable features={features} />}
      </div>
    );
  }
}

createRoot(document.getElementById('wrapper')).render(<CloudFileAdmin />);
