from rest_framework.routers import DefaultRouter
from auth.api_views import AuthViewSet

app_name = "auth"

router = DefaultRouter()
router.register(r'', AuthViewSet, basename='auth')

urlpatterns = router.urls
