from pickle import TRUE
from turtle import distance
from django.db import models
from django.contrib.auth.hashers import make_password

# Create your models here.

class Seller(models.Model): 
    SellerID = models.AutoField(primary_key=True)
    Sname = models.CharField(max_length=50) 
    password = models.CharField(max_length=255)
    Saddress = models.EmailField() 
    Sphone_number = models.BigIntegerField() 
#    Semail = models.EmailField()
    
    def save(self, *args, **kwargs):
        # Hash password before saving if it's not already hashed
        if not self.password.startswith(('pbkdf2_sha256$', 'bcrypt$', 'argon2')):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.Sname
     
    def __str__(self):
        return self.Sname


class Buyer(models.Model):
    BuyerID = models.AutoField(primary_key=True)
    Bname = models.CharField(max_length=50) 
#    Bemail = models.EmailField() 
    Baddress = models.EmailField() 
    Bphone_number = models.BigIntegerField() 
    password = models.CharField(max_length=255)
    
    def save(self, *args, **kwargs):
        # Hash password before saving if it's not already hashed
        if not self.password.startswith(('pbkdf2_sha256$', 'bcrypt$', 'argon2')):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.Bname


class Amenities(models.Model):  
    AmenitiesID = models.AutoField(primary_key=True)
    Address=models.CharField(max_length=50) 
    Land_area=models.BigIntegerField() 
    Soil_type=models.CharField(max_length=30) 
    Amount=models.BigIntegerField()
    water_sources=models.CharField(max_length=50) 
    suitable_crop=models.CharField(max_length=50) 
    weather=models.CharField(max_length=30) 
    protection_type=models.CharField(max_length=50)
#    distance_from_mainroad=models.BigIntegerField() 
    contains=models.ManyToManyField(Buyer)
    containss=models.ManyToManyField(Seller)
    
    def __str__(self):
        return self.Address
    
    def __str__(self):
        return self.contains
    
    def __str__(self):
        return self.containss
    
    def __str__(self):
        return str(self.AmenitiesID)


class Land(models.Model):  
    LandID = models.AutoField(primary_key=True)
    owns = models.ForeignKey(Seller, on_delete=models.CASCADE)
    buys = models.ForeignKey(Buyer, on_delete=models.CASCADE, null=True, blank=True)
    Address = models.CharField(max_length=50)  # Now required
    Soil_type = models.CharField(max_length=30)  # Now required
    water_sources = models.CharField(max_length=50)  # Now required
    Land_area = models.CharField(max_length=50)  # Now required
    suitable_crop = models.CharField(max_length=50)  # Now required
    weather = models.CharField(max_length=30)  # Now required
    protection_type = models.CharField(max_length=50)  # Now required
    Amount = models.CharField(max_length=50)  # Now required


class Broker(models.Model): 
    BrokerID = models.AutoField(primary_key=True)
    Brname = models.CharField(max_length=50) 
    Brphone_number = models.BigIntegerField() 
#    Br_experience = models.BigIntegerField() 
#    commission_percentage = models.BigIntegerField()
    helps = models.ManyToManyField(Buyer)
    password = models.CharField(max_length=255)
    address = models.EmailField()
#    Bremail = models.EmailField() 
    
    def save(self, *args, **kwargs):
        # Hash password before saving if it's not already hashed
        if not self.password.startswith(('pbkdf2_sha256$', 'bcrypt$', 'argon2')):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.Brname
    
    def __str__(self):
        return self.helps
    
    def __str__(self):
        return str(self.BrokerID)
