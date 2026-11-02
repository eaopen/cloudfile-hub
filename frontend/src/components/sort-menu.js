import React from 'react';
import PropTypes from 'prop-types';
import { gettext } from '@/utils/constants';
import CustomDropdown from './dropdown';
import Icon from './icon';
import Tooltip from './tooltip';

const propTypes = {
  className: PropTypes.string,
  sortBy: PropTypes.string,
  sortOrder: PropTypes.string,
  sortOptions: PropTypes.array,
  // Whether the list behind this menu is the complete listing for the folder.
  // Only a complete client-side list may be sorted by keys that have no
  // server-side ordering (see `requiresCompleteList` below).
  isCompleteList: PropTypes.bool,
  onSelectSortOption: PropTypes.func.isRequired
};

const DEFAULT_SORT_OPTIONS = [
  { value: 'name-asc', text: gettext('Ascending by name') },
  { value: 'name-desc', text: gettext('Descending by name') },
  { value: 'size-asc', text: gettext('Ascending by size') },
  { value: 'size-desc', text: gettext('Descending by size') },
  { value: 'time-asc', text: gettext('Ascending by time') },
  { value: 'time-desc', text: gettext('Descending by time') }
];

// Extension sorting is available only for fully loaded directory lists.
// Other consumers (tag files, administration, etc.) keep their own sort options.
// The ext keys have no server-side counterpart, so a server-paged directory
// must never offer them: sorting one native page in the browser would present
// a page-local order as the folder's global order.
export const DIRECTORY_SORT_OPTIONS = [
  ...DEFAULT_SORT_OPTIONS,
  { value: 'ext-asc', text: gettext('Ascending by type'), requiresCompleteList: true },
  { value: 'ext-desc', text: gettext('Descending by type'), requiresCompleteList: true }
];

// Filter at render time, not in the constructor: a caller may flip
// `isCompleteList` after mount (for example once paging reaches the end), and
// the constructor caches `sortOptions` on the instance.
export const filterSortOptions = (sortOptions, isCompleteList) => {
  return sortOptions.filter((option) => isCompleteList || !option.requiresCompleteList);
};

class SortMenu extends React.Component {
  constructor(props) {
    super(props);
    this.sortOptions = this.props.sortOptions || DEFAULT_SORT_OPTIONS;
  }

  buildSortMenuItems = ({ sortOptions, sortBy, sortOrder }) => {
    return filterSortOptions(sortOptions, this.props.isCompleteList).map((item) => ({
      key: item.value,
      label: item.text,
      checked: item.value === `${sortBy}-${sortOrder}`,
      sortOption: item,
      onClick: () => this.props.onSelectSortOption(item)
    }));
  };

  renderCustomTrigger = (isOpen) => {
    return (
      <>
        <Icon symbol="sort" />
        {!isOpen && <Tooltip target="sort-icon">{gettext('Switch sort mode')}</Tooltip>}
      </>
    );
  };

  render() {
    const { sortBy, sortOrder, className } = this.props;
    const sortOptions = this.buildSortMenuItems({ sortOptions: this.sortOptions, sortBy, sortOrder });

    return (
      <CustomDropdown
        target="sort-icon"
        items={sortOptions}
        variant="action"
        className={className || ''}
        trigger={this.renderCustomTrigger}
        triggerClassName="cur-view-path-btn px-1"
        toggleProps={{ 'aria-label': gettext('Switch sort mode') }}
        menuPortal={false}
      />
    );
  }

}

SortMenu.propTypes = propTypes;

// Fail closed: a caller that does not declare a complete listing must not get
// options that only make sense for one.
SortMenu.defaultProps = {
  isCompleteList: false
};

export default SortMenu;
