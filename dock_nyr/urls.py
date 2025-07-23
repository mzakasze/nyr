from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('nyr/', views.stock_list, name='stock_list'),
    path('nyr/<int:stock_id>/edit/', views.edit_stock, name='edit_stock'),
    path('nyr/<int:stock_id>/delete/', views.delete_stock, name='delete_stock'),
    path('nyr_add/', views.add_stock, name='add_stock'),
    # <<< ZMIANA START: Dodano URL dla Quick Add >>>
    path('nyr/quick_add/', views.quick_add_stock, name='quick_add_stock'),
    # <<< ZMIANA KONIEC >>>
    path('nyr_summary/', views.nyr_summary, name='nyr_summary'),
    path('nyr_summary/clear/', views.clear_summary_stocks, name='clear_summary_stocks'),
    path('nyr/rotom/', views.rotom_list, name='rotom_list'),
    # <<< ZMIANA START: Dodano URL dla historii ROTOM >>>
    path('nyr/rotom/<str:trailer_id>/history/', views.rotom_history, name='rotom_history'),
    # <<< ZMIANA KONIEC >>>
]