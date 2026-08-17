import React, { Fragment } from 'react';
import PropTypes from 'prop-types';
import RepoInfoBar from '../../components/repo-info-bar';
import DirentGridView from '../../components/dirent-grid-view/dirent-grid-view';
import DirentNoneView from '../../components/dirent-list-view/dirent-none-view';
import { gettext } from '../../utils/constants';

const propTypes = {
  path: PropTypes.string.isRequired,
  repoID: PropTypes.string.isRequired,
  currentRepoInfo: PropTypes.object.isRequired,
  usedRepoTags: PropTypes.array.isRequired,
  updateUsedRepoTags: PropTypes.func.isRequired,
  direntList: PropTypes.array.isRequired,
  selectedDirentList: PropTypes.array.isRequired,
  onSelectedDirentListUpdate: PropTypes.func.isRequired,
  onItemClick: PropTypes.func.isRequired,
  onGridItemClick: PropTypes.func,
  onItemDelete: PropTypes.func.isRequired,
  onItemMove: PropTypes.func.isRequired,
  onItemConvert: PropTypes.func.isRequired,
  onItemsMove: PropTypes.func.isRequired,
  onItemsDelete: PropTypes.func.isRequired,
  isGroupOwnedRepo: PropTypes.bool.isRequired,
  userPerm: PropTypes.string,
  isRepoInfoBarShow: PropTypes.bool.isRequired,
  isDirentListLoading: PropTypes.bool.isRequired,
  enableDirPrivateShare: PropTypes.bool.isRequired,
  updateDirent: PropTypes.func.isRequired,
  showDirentDetail: PropTypes.func.isRequired,
  repoTags: PropTypes.array.isRequired,
  onFileTagChanged: PropTypes.func,
  fullDirentList: PropTypes.array,
  getMenuContainerSize: PropTypes.func,
  eventBus: PropTypes.object,
  updateTreeNode: PropTypes.func,
};

class DirGridView extends React.Component {

  onToggleSelectAll = () => {
    const { direntList, selectedDirentList, onSelectedDirentListUpdate } = this.props;
    const isAllSelected = selectedDirentList.length === direntList.length;
    onSelectedDirentListUpdate(isAllSelected ? [] : direntList);
  };

  render() {
    if (this.props.path === '/' && this.props.direntList.length === 0) {
      return (
        <DirentNoneView
          path={this.props.path}
          isDirentListLoading={this.props.isDirentListLoading}
          currentRepoInfo={this.props.currentRepoInfo}
          userPerm={this.props.userPerm}
          eventBus={this.props.eventBus}
          getMenuContainerSize={this.props.getMenuContainerSize}
        />
      );
    }
    return (
      <Fragment>
        {this.props.isRepoInfoBarShow && (
          <RepoInfoBar
            repoID={this.props.repoID}
            currentPath={this.props.path}
            usedRepoTags={this.props.usedRepoTags}
            updateUsedRepoTags={this.props.updateUsedRepoTags}
            onFileTagChanged={this.props.onFileTagChanged}
          />
        )}
        {this.props.direntList.length > 0 && (
          <div className="grid-view-select-all" style={{ padding: '0 8px', fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <input
              type="checkbox"
              id="grid-view-select-all-checkbox"
              checked={this.props.selectedDirentList.length === this.props.direntList.length}
              onChange={this.onToggleSelectAll}
            />
            <label htmlFor="grid-view-select-all-checkbox">{gettext('Select all')}</label>
          </div>
        )}
        <DirentGridView
          path={this.props.path}
          repoID={this.props.repoID}
          currentRepoInfo={this.props.currentRepoInfo}
          isGroupOwnedRepo={this.props.isGroupOwnedRepo}
          userPerm={this.props.userPerm}
          enableDirPrivateShare={this.props.enableDirPrivateShare}
          direntList={this.props.direntList}
          fullDirentList={this.props.fullDirentList}
          selectedDirentList={this.props.selectedDirentList}
          onSelectedDirentListUpdate={this.props.onSelectedDirentListUpdate}
          onItemClick={this.props.onItemClick}
          onItemDelete={this.props.onItemDelete}
          onItemMove={this.props.onItemMove}
          onItemConvert={this.props.onItemConvert}
          onItemsMove={this.props.onItemsMove}
          onItemsDelete={this.props.onItemsDelete}
          isDirentListLoading={this.props.isDirentListLoading}
          updateDirent={this.props.updateDirent}
          showDirentDetail={this.props.showDirentDetail}
          onGridItemClick={this.props.onGridItemClick}
          repoTags={this.props.repoTags}
          onFileTagChanged={this.props.onFileTagChanged}
          getMenuContainerSize={this.props.getMenuContainerSize}
          eventBus={this.props.eventBus}
          updateTreeNode={this.props.updateTreeNode}
        />
      </Fragment>
    );
  }
}

DirGridView.propTypes = propTypes;

export default DirGridView;
