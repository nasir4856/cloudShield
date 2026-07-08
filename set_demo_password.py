from app import create_app
from app.models import AdminUser
from extensions import db
from werkzeug.security import generate_password_hash

app = create_app()
with app.app_context():
    user = AdminUser.query.filter_by(username='admin').first()
    if user is None:
        raise SystemExit('No admin user found')
    user.password_hash = generate_password_hash('admin123')
    db.session.commit()
    print('Updated admin password successfully')
