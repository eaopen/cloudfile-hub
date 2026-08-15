import React from 'react';
import PropTypes from 'prop-types';
import { Modal, ModalBody, ModalFooter, Button } from 'reactstrap';
import { gettext } from '../../utils/constants';

const propTypes = {
  affectedMembers: PropTypes.number.isRequired,
  onConfirm: PropTypes.func.isRequired,
  onCancel: PropTypes.func.isRequired,
};

const MovePermissionConfirmDialog = ({ affectedMembers, onConfirm, onCancel }) => {
  return (
    <Modal isOpen={true} toggle={onCancel} centered>
      <ModalBody>
        <p>
          {gettext('Moving will inherit the destination folder permissions. {n} current member(s) may lose access. Continue?').replace('{n}', affectedMembers)}
        </p>
      </ModalBody>
      <ModalFooter>
        <Button color="secondary" onClick={onCancel}>{gettext('Cancel')}</Button>
        <Button color="primary" onClick={onConfirm}>{gettext('Continue')}</Button>
      </ModalFooter>
    </Modal>
  );
};

MovePermissionConfirmDialog.propTypes = propTypes;

export default MovePermissionConfirmDialog;
