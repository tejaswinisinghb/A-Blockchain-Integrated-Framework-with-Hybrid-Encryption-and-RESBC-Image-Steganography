from django.urls import path

from . import views

urlpatterns = [path("index.html", views.index, name="index"),
	             path("UserLogin", views.UserLogin, name="UserLogin"),
		     path("UserLoginAction", views.UserLoginAction, name="UserLoginAction"),
		     path("Register", views.Register, name="Register"),
		     path("RegisterAction", views.RegisterAction, name="RegisterAction"),		
		     path("UploadImage", views.UploadImage, name="UploadImage"),
		     path("UploadImageAction", views.UploadImageAction, name="UploadImageAction"),	
		     path("HybridEncryption", views.HybridEncryption, name="HybridEncryption"),
		     path("KeyVerification", views.KeyVerification, name="KeyVerification"),
		     path("DataDecryption", views.DataDecryption, name="DataDecryption"),	
		     path("Verify", views.Verify, name="Verify"),
		     path("DecryptAction", views.DecryptAction, name="DecryptAction"),	
		    ]