"""Administrator-triggered eTech directory reconciliation."""
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from seahub.api2.authentication import TokenAuthentication
from seahub.api2.base import APIView
from seahub.api2.throttling import UserRateThrottle

from . import reconcile, snapshot
from .sync import sync


logger = logging.getLogger(__name__)


class DirectorySync(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)
    http_method_names = ('post',)

    def post(self, request):
        try:
            result = sync()
        except reconcile.SyncRefused as error:
            result = {'status': 'REFUSED', 'detail': str(error)}
        except (snapshot.SnapshotRejected, ValueError) as error:
            result = {'status': 'ERROR', 'detail': str(error)}
        except Exception:
            logger.exception('Directory sync failed')
            result = {'status': 'ERROR', 'detail': 'Directory sync is unavailable'}
        response = Response(result)
        response['Cache-Control'] = 'no-store'
        return response
