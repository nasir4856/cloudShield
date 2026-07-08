from app import create_app
from app.models import AdminUser

app = create_app()
app.testing = True
client = app.test_client()

with app.app_context():
    admin = AdminUser.query.filter_by(username='admin').first()
    assert admin is not None
    with client.session_transaction() as sess:
        sess['admin_authenticated'] = True
        sess['user_id'] = admin.id
    for path in ['/admin/reports', '/admin/monitoring']:
        resp = client.get(path)
        print(path, resp.status_code)
        text = resp.get_data(as_text=True)
        for needle in ['Threat Posture','Application Activity','Protection Coverage','Operations Snapshot','Open Threat Explorer','Go to Monitoring','Open Reports','Manage Rules']:
            print(needle, needle in text)
