from django.urls import path, include
from django.http import HttpResponse
from pathlib import Path


from django.views.decorators.csrf import ensure_csrf_cookie

@ensure_csrf_cookie
def serve_frontend(request):
    html_file = Path(__file__).resolve().parent.parent / 'templates' / 'index.html'
    html = html_file.read_text(encoding='utf-8')
    return HttpResponse(html, content_type='text/html')


urlpatterns = [
    path('', serve_frontend, name='home'),
    path('api/auth/', include('auth_app.urls')),
]
