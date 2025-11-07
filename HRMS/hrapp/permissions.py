from rest_framework.permissions import BasePermission

def _roles_for_view(view):
    roles = None
    if hasattr(view, "allowed_roles_by_action") and isinstance(view.allowed_roles_by_action, dict):
        act = getattr(view, "action", None)
        roles = view.allowed_roles_by_action.get(act)
    if roles is None:
        roles = getattr(view, "allowed_roles", None)
    return roles

class RolePermission(BasePermission):
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        roles = _roles_for_view(view)
        return True if not roles else getattr(request.user, "role", None) in roles
    
    
class IsOwnerOrRoleAllowed(BasePermission):
    def has_object_permission(self, request, view, obj):
        if not (request.user and request.user.is_authenticated):
            return False
        roles = _roles_for_view(view) or []
        if getattr(request.user, "role", None) in roles:
            return True
        if hasattr(obj, "user"):
            return obj.user == request.user
        if hasattr(obj, "employee"):
            return getattr(obj.employee, "user", None) == request.user
        return False
