# Generated by Django 5.1.7 on 2025-04-01 02:12

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Buyer',
            fields=[
                ('BuyerID', models.AutoField(primary_key=True, serialize=False)),
                ('Bname', models.CharField(max_length=50)),
                ('Baddress', models.EmailField(max_length=254)),
                ('Bphone_number', models.BigIntegerField()),
                ('password', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Seller',
            fields=[
                ('SellerID', models.AutoField(primary_key=True, serialize=False)),
                ('Sname', models.CharField(max_length=50)),
                ('password', models.CharField(max_length=255)),
                ('Saddress', models.EmailField(max_length=254)),
                ('Sphone_number', models.BigIntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Broker',
            fields=[
                ('BrokerID', models.AutoField(primary_key=True, serialize=False)),
                ('Brname', models.CharField(max_length=50)),
                ('Brphone_number', models.BigIntegerField()),
                ('password', models.CharField(max_length=255)),
                ('address', models.EmailField(max_length=254)),
                ('helps', models.ManyToManyField(to='LMS.buyer')),
            ],
        ),
        migrations.CreateModel(
            name='Land',
            fields=[
                ('LandID', models.AutoField(primary_key=True, serialize=False)),
                ('Address', models.CharField(max_length=50)),
                ('Soil_type', models.CharField(max_length=30)),
                ('water_sources', models.CharField(max_length=50)),
                ('Land_area', models.CharField(max_length=50)),
                ('suitable_crop', models.CharField(max_length=50)),
                ('weather', models.CharField(max_length=30)),
                ('protection_type', models.CharField(max_length=50)),
                ('Amount', models.CharField(max_length=50)),
                ('buys', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='LMS.buyer')),
                ('owns', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LMS.seller')),
            ],
        ),
        migrations.CreateModel(
            name='Amenities',
            fields=[
                ('AmenitiesID', models.AutoField(primary_key=True, serialize=False)),
                ('Address', models.CharField(max_length=50)),
                ('Land_area', models.BigIntegerField()),
                ('Soil_type', models.CharField(max_length=30)),
                ('Amount', models.BigIntegerField()),
                ('water_sources', models.CharField(max_length=50)),
                ('suitable_crop', models.CharField(max_length=50)),
                ('weather', models.CharField(max_length=30)),
                ('protection_type', models.CharField(max_length=50)),
                ('contains', models.ManyToManyField(to='LMS.buyer')),
                ('containss', models.ManyToManyField(to='LMS.seller')),
            ],
        ),
    ]
