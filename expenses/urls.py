from django.urls import path

from expenses import views


urlpatterns = [
    path('', views.ListExpensesView.as_view(), name='list-expenses'),
    path('add/', views.AddExpenseView.as_view(), name='add-expense'),
    path('<int:id>/', views.ExpenseRUDView.as_view(), name='expense-rud'),
]
