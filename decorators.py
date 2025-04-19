from functools import wraps
from flask import request

def log_admin_action(action=None, entity=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated and current_user.is_admin:
                # Get record ID from URL parameters if exists
                record_id = kwargs.get('user_id') or kwargs.get('farm_id') or kwargs.get('animal_id') or kwargs.get('transfer_id')
                
                # Log before action
                current_user.log_admin_action(
                    action=f"Attempting {action or f.__name__}",
                    entity=entity,
                    record_id=record_id,
                    request=request
                )
                
                result = f(*args, **kwargs)
                
                # Log after successful action
                current_user.log_admin_action(
                    action=f"Completed {action or f.__name__}",
                    entity=entity,
                    record_id=record_id,
                    details=f"Admin action completed successfully",
                    request=request
                )
                
                return result
            return f(*args, **kwargs)
        return decorated_function
    return decorator