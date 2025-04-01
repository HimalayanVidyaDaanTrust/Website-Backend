from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import Profile

@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_profile(sender, instance, created, **kwargs):
    # Skip this if we just created the user (the create_profile handler will handle it)
    if not created:
        # Get or create the profile to handle users that existed before signals were set up
        profile, created = Profile.objects.get_or_create(user=instance)
        if not created:
            profile.save()