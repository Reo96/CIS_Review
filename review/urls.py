from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('upload/', views.upload_config, name='upload_config'),
    path('result/', views.review_result, name='review_result'),
]
