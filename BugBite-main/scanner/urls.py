from django.urls import path
from . import views
urlpatterns = [
    path('new_scan/',views.home,name='home'),
    path('result/',views.result,name='result'),

    path('pdf',views.GeneratePdf,name='pdf'),

    path('view_project/',views.view_project,name='project'),
    path('view_details/<int:pk>/', views.view_details, name='view_details'),
    path('project/<int:pk>/export-pdf/', views.export_pdf, name='export_pdf'),
    path('project/<int:project_id>/delete/', views.delete_project, name='delete_project'),

    

    
]