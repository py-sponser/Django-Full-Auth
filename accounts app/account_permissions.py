from rest_framework.permissions import BasePermission


class IsNotActivated(BasePermission):
    """
    Allows access only to not-activated users.
    """

    def has_permission(self, request, view):
        return bool(request.user and not request.user.is_active)


class IsNotAuthenticated(BasePermission):
    """
    Allows access only to unauthenticated users.
    """

    def has_permission(self, request, view):
        return bool(request.user and not request.user.is_authenticated)

