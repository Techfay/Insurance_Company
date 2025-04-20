from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),  # dashboard
    path('policies/', views.policy_list, name='policy_list'), # policy
    path('policies/new/', views.policy_create, name='policy_create'), # policy new
    path('policies/<int:pk>/edit/', views.policy_update, name='policy_update'), # policy edit
    path('policies/<int:pk>/delete/', views.policy_delete, name='policy_delete'), # policy delete
    path('claims/', views.claim_list, name='claim_list'), # claim
    path('claims/new/', views.claim_create, name='claim_create'), #claim new
    path('claims/review/', views.claim_review, name='claim_review'), # claimreview
    path('claims/<int:pk>/<str:action>/', views.claim_process, name='claim_process'), # claim init
    path('reports/', views.reports, name='reports'), # for report page
    path('/dashboard/reports', views.reports, name='reports'), # for report page
    # path('dashboard/', views.customer_dashboard, name='dashboard'),
    path('my-policies/', views.my_policies, name='my_policies'),
    path('available-policies/', views.available_policies, name='available_policies'),
    path('policy/purchase/<int:policy_id>/', views.policy_purchase, name='policy_purchase'),
    path('policy/payment-success/<int:policy_id>/', views.payment_success, name='payment_success'),
    path('agent-dashboard/', views.dashboard, name='agent_dashboard'),
    path('agent-available-policies/', views.agent_available_policies, name='agent_available_policies'),
    path('agent-sales-performance/', views.agent_sales_performance, name='agent_sales_performance'),
    path('sell-policy/<int:policy_id>/', views.sell_policy, name='sell_policy'),
    # path('premium-calculator/', views.premium_calculator, name='premium_calculator'),
    path('life-premium-calculator/', views.life_premium_calculator, name='life_premium_calculator'),
    path('health-premium-calculator/', views.health_premium_calculator, name='health_premium_calculator'),
    path('vehicle-premium-calculator/', views.vehicle_premium_calculator, name='vehicle_premium_calculator'),
     path('premium-calculator-overview/', views.premium_calculator_overview, name='premium_calculator_overview'),

]
