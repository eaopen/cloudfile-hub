import React, { useState, useRef, useEffect } from 'react';
import { Button, Modal, Input, ModalBody, ModalFooter, Alert } from 'reactstrap';
import PropTypes from 'prop-types';
import SeahubModalHeader from '@/components/seahub-modal-header';
import { gettext } from '@/utils/constants';
import { isEnter } from '@/utils/hotkey';
import { normalizeNewFileNameInput, validateNewFileName } from '@/utils/new-file-name';
import { validateName } from '@/utils/utils';

const RenameDialog = ({ isDir, oldName, onSubmit, onCancel }) => {
  const [newName, setNewName] = useState('');
  const [errMessage, setErrMessage] = useState('');
  const [isSubmitBtnActive, setIsSubmitBtnActive] = useState(false);
  const newInput = useRef(null);

  const handleChange = (e) => {
    const value = e.target.value;
    setNewName(value);
    setIsSubmitBtnActive(!!value.trim());
  };

  const handleSubmit = () => {
    // Keep an unedited legacy filename unchanged; only new input is normalized.
    if (newName === oldName) {
      onCancel();
      return;
    }
    const submittedName = normalizeNewFileNameInput(newName);
    if (submittedName === oldName) {
      onCancel();
      return;
    }
    const policy = validateNewFileName(submittedName);
    const { isValid, errMessage } = policy.isValid ? validateName(submittedName) : policy;
    if (!isValid) {
      setErrMessage(errMessage);
      return;
    }

    onSubmit(submittedName);
  };

  const handleKeyDown = (e) => {
    if (isEnter(e)) {
      handleSubmit();
    }
  };

  const onAfterModelOpened = () => {
    if (!newInput.current) return;
    newInput.current.focus();
    if (!isDir) {
      const endIndex = oldName.lastIndexOf('.');
      if (endIndex !== -1) {
        newInput.current.setSelectionRange(0, endIndex, 'forward');
      } else {
        newInput.current.setSelectionRange(0, oldName.length, 'forward');
      }
    } else {
      newInput.current.setSelectionRange(0, -1);
    }
  };

  useEffect(() => {
    setNewName(oldName);
  }, [oldName]);

  return (
    <Modal isOpen={true} toggle={onCancel} onOpened={onAfterModelOpened}>
      <SeahubModalHeader toggle={onCancel}>
        {isDir ? gettext('Rename Folder') : gettext('Rename File')}
      </SeahubModalHeader>
      <ModalBody>
        <p>{isDir ? gettext('New folder name') : gettext('New file name')}</p>
        <Input
          onKeyDown={handleKeyDown}
          innerRef={newInput}
          value={newName}
          onChange={handleChange}
        />
        {errMessage && <Alert color="danger" className="mt-2">{errMessage}</Alert>}
      </ModalBody>
      <ModalFooter>
        <Button color="secondary" onClick={onCancel}>{gettext('Cancel')}</Button>
        <Button color="primary" onClick={handleSubmit} disabled={!isSubmitBtnActive}>{gettext('Submit')}</Button>
      </ModalFooter>
    </Modal>
  );
};

RenameDialog.propTypes = {
  isDir: PropTypes.bool.isRequired,
  oldName: PropTypes.string.isRequired,
  onSubmit: PropTypes.func.isRequired,
  onCancel: PropTypes.func.isRequired,
};

export default RenameDialog;
