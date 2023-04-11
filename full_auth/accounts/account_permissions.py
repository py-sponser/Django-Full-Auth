from rest_framework.permissions import BasePermission


class IsNotAuthenticated(BasePermission):
    """
    Allows access only to unauthenticated users.
    """

    def has_permission(self, request, view):
        return bool(request.user and not request.user.is_authenticated)

