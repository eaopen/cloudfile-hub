import React from 'react';
import PropTypes from 'prop-types';
import classnames from 'classnames';
import { Utils } from '../../utils/utils';
import { gettext } from '../../utils/constants';
import IconBtn from '../icon-btn';

const propTypes = {
  item: PropTypes.object.isRequired,
  idx: PropTypes.number.isRequired,
  onItemClickHandler: PropTypes.func.isRequired,
  isHighlight: PropTypes.bool,
  setRef: PropTypes.func,
  onHighlightIndex: PropTypes.func,
  timer: PropTypes.number,
  onSetTimer: PropTypes.func,
  onDeleteItem: PropTypes.func,
};

class SearchResultItem extends React.Component {

  constructor(props) {
    super(props);
    this.controller = null;
  }

  onClickHandler = () => {
    this.props.onItemClickHandler(this.props.item);
  };

  onMouseEnter = () => {
    if (this.props.isHighlight) return;
    if (this.controller) {
      this.controller.abort();
    }
    this.controller = new AbortController();

    if (this.props.onHighlightIndex) {
      this.props.onHighlightIndex(this.props.idx);
    }
  };

  deleteItem = (e) => {
    e.stopPropagation();
    this.props.onDeleteItem(this.props.item);
  };

  render() {
    const { item, onDeleteItem, isHighlight, setRef = (() => {}) } = this.props;
    let folderIconUrl = item.path === '/' ? Utils.getDefaultLibIconUrl() : Utils.getFolderIconUrl(false, 192);
    let fileIconUrl = item.is_dir ? folderIconUrl : Utils.getFileIconUrl(item.name);
    let showName = item.repo_name + item.path;
    showName = showName.endsWith('/') ? showName.slice(0, showName.length - 1) : showName;

    if (item.thumbnail_url) {
      fileIconUrl = item.thumbnail_url;
    }

    return (
      <li
        className={classnames('search-result-item', { 'search-result-item-highlight': isHighlight })}
        onClick={this.onClickHandler}
        ref={ref => setRef(ref)}
        onMouseEnter={this.onMouseEnter}
        tabIndex={0}
        role="option"
        aria-selected={isHighlight}
        onKeyDown={Utils.onKeyDown}
      >
        <img className={item.path === '/' ? 'item-img' : 'lib-item-img'} src={fileIconUrl} alt="" />
        <div className="item-content">
          <div className="item-name ellipsis" title={item.name}>{item.name}</div>
          <div className="item-link ellipsis" title={showName}>{showName}</div>
          <div className="item-text ellipsis" dangerouslySetInnerHTML={{ __html: item.content }}></div>
          {item.is_dir && (
            <div className="item-folder-action ellipsis" style={{ fontSize: '12px', color: '#999', marginTop: '2px' }}>
              {gettext('Open folder')} · {gettext('Locate in directory tree')}
            </div>
          )}
          {item.matched_tags && item.matched_tags.length > 0 && (
            <div className="item-matched-tags" style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
              {item.matched_tags.map((tag, index) => (
                <span key={index} className="matched-tag-badge" style={{ backgroundColor: '#f0f0f0', borderRadius: '10px', padding: '0 8px', fontSize: '12px', color: '#666' }}>
                  {gettext('Matched tag')}: {tag}
                </span>
              ))}
            </div>
          )}
        </div>
        {isHighlight && onDeleteItem && (
          <IconBtn
            symbol="close"
            className="search-icon-right"
            onClick={this.deleteItem}
            aria-label={gettext('Delete')}
          />
        )}
      </li>
    );
  }
}

SearchResultItem.propTypes = propTypes;

export default SearchResultItem;
