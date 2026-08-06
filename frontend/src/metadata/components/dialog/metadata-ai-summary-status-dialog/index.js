import React, { useState, useCallback } from 'react';
import PropTypes from 'prop-types';
import { ModalBody, ModalFooter, Button } from 'reactstrap';
import Switch from '../../../../components/switch';
import { gettext } from '../../../../utils/constants';
import metadataAPI from '../../../api';
import toaster from '../../../../components/toast';
import { Utils } from '../../../../utils/utils';
import TurnOffConfirmDialog from '../turn-off-confirm-dialog';
import { EVENT_BUS_TYPE } from '../../../constants';

import '../metadata-face-recognition-dialog/index.css';

const MetadataAISummaryStatusDialog = ({ value: oldValue, repoID, toggleDialog: toggle, submit, enableMetadata }) => {
  const [value, setValue] = useState(oldValue);
  const [submitting, setSubmitting] = useState(false);
  const [showTurnOffConfirmDialog, setShowTurnOffConfirmDialog] = useState(false);

  const onToggle = useCallback(() => {
    toggle();
  }, [toggle]);

  const onSubmit = useCallback(() => {
    if (!value) {
      setShowTurnOffConfirmDialog(true);
      return;
    }
    setSubmitting(true);
    metadataAPI.openAISummary(repoID).then(() => {
      submit(true);
      window.sfMetadataContext?.eventBus?.dispatch(EVENT_BUS_TYPE.RELOAD_DATA);
      toggle();
    }).catch(error => {
      const errorMsg = Utils.getErrorMsg(error);
      toaster.danger(errorMsg);
      setSubmitting(false);
    });
  }, [repoID, submit, toggle, value]);

  const turnOffConfirmToggle = useCallback(() => {
    setShowTurnOffConfirmDialog(!showTurnOffConfirmDialog);
  }, [showTurnOffConfirmDialog]);

  const turnOffConfirmSubmit = useCallback(() => {
    setShowTurnOffConfirmDialog(false);
    setSubmitting(true);
    metadataAPI.closeAISummary(repoID).then(() => {
      submit(false);
      window.sfMetadataContext?.eventBus?.dispatch(EVENT_BUS_TYPE.RELOAD_DATA);
      toggle();
    }).catch(error => {
      const errorMsg = Utils.getErrorMsg(error);
      toaster.danger(errorMsg);
      setSubmitting(false);
    });
  }, [repoID, submit, toggle]);

  const onValueChange = useCallback(() => {
    setValue(!value);
  }, [value]);

  return (
    <>
      {!showTurnOffConfirmDialog && (
        <>
          <ModalBody className="metadata-face-recognition-dialog">
            {!enableMetadata && <p className="open-metadata-tip">{gettext('Please turn on extended properties setting first')}</p>}
            <Switch
              checked={value}
              disabled={submitting || !enableMetadata}
              size="large"
              textPosition="right"
              className="change-face-recognition-status-management w-100"
              onChange={onValueChange}
              placeholder={gettext('AI summary')}
            />
            <p className="tip m-0">
              {gettext('Enable AI summary to generate concise summaries for supported documents in this library.')}
            </p>
          </ModalBody>
          <ModalFooter>
            <Button color="secondary" onClick={onToggle}>{gettext('Cancel')}</Button>
            <Button color="primary" disabled={oldValue === value || submitting || !enableMetadata} onClick={onSubmit}>{gettext('Submit')}</Button>
          </ModalFooter>
        </>
      )}
      {showTurnOffConfirmDialog && (
        <TurnOffConfirmDialog title={gettext('Turn off AI summary')} toggle={turnOffConfirmToggle} submit={turnOffConfirmSubmit}>
          <p>{gettext('Do you really want to turn off AI summary? Existing AI summaries will all be deleted.')}</p>
        </TurnOffConfirmDialog>
      )}
    </>
  );
};

MetadataAISummaryStatusDialog.propTypes = {
  value: PropTypes.bool.isRequired,
  repoID: PropTypes.string.isRequired,
  toggleDialog: PropTypes.func.isRequired,
  submit: PropTypes.func.isRequired,
  enableMetadata: PropTypes.bool.isRequired,
};

export default MetadataAISummaryStatusDialog;
