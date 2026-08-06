import React, { useContext, useEffect, useCallback, useState, useRef, forwardRef, useImperativeHandle } from 'react';
import ModalPortal from '../../components/modal-portal';
import LibSubFolderPermissionDialog from '../../components/dialog/lib-sub-folder-permission-dialog';
import { EVENT_BUS_TYPE } from '../../components/common/event-bus-type';
import { folderPermEnabled, isPro, siteRoot } from '../../utils/constants';

// This hook provides content about lib sub-folder permission
const LibSubFolderPermissionContext = React.createContext(null);

export const LibSubFolderPermissionProvider = forwardRef(({ repoID, eventBus, isGroupOwnedRepo, children }, ref) => {
  const [isDialogShow, setDialogShow] = useState();

  const pathRef = useRef('');
  const nameRef = useRef('');

  const handleLibSubFolderPermission = useCallback((path, name) => {
    if (folderPermEnabled && !isPro) {
      const query = new URLSearchParams({ repo_id: repoID, path });
      window.location.assign(`${siteRoot}cloudfile/acl/?${query.toString()}`);
      return;
    }
    pathRef.current = path;
    nameRef.current = name;
    setDialogShow(true);
  }, [repoID]);

  const cancelLibSubFolderPermission = useCallback(() => {
    setDialogShow(false);
    pathRef.current = '';
    nameRef.current = '';
  }, []);

  useEffect(() => {
    const unsubscribeCreateFile = eventBus.subscribe(EVENT_BUS_TYPE.PERMISSION, handleLibSubFolderPermission);
    return () => {
      unsubscribeCreateFile();
    };
  }, [eventBus, handleLibSubFolderPermission]);

  useImperativeHandle(ref, () => ({
    handleLibSubFolderPermission,
    cancelLibSubFolderPermission,
  }), [handleLibSubFolderPermission, cancelLibSubFolderPermission]);

  return (
    <LibSubFolderPermissionContext.Provider value={{ eventBus, handleLibSubFolderPermission }}>
      {children}
      {isDialogShow && (
        <ModalPortal>
          <LibSubFolderPermissionDialog
            isDepartmentRepo={isGroupOwnedRepo}
            repoID={repoID}
            folderPath={pathRef.current}
            folderName={nameRef.current}
            toggleDialog={cancelLibSubFolderPermission}
          />
        </ModalPortal>
      )}
    </LibSubFolderPermissionContext.Provider>
  );
});

export const useLibSubFolderPermissionContext = () => {
  const context = useContext(LibSubFolderPermissionContext);
  if (!context) {
    throw new Error('\'LibSubFolderPermissionContext\' is null');
  }
  return context;
};
