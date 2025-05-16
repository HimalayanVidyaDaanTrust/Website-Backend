from django.db.models.signals import post_save,post_delete, pre_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import Profile, Student,Gallery,Camp
from django.db import models,transaction

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

@receiver(post_delete)
def delete_files_when_row_deleted_from_db(sender, instance, **kwargs):
    """Delete files when model instance is deleted"""
    for field in sender._meta.concrete_fields:
        if isinstance(field, models.FileField):
            instance_file_field = getattr(instance, field.name)
            delete_file_if_unused(sender, instance, field, instance_file_field)

@receiver(pre_save)
def delete_files_when_file_changed(sender, instance, **kwargs):
    """Delete files when file field is updated with new file"""
    # Don't run on initial save
    if not instance.pk:
        return
        
    for field in sender._meta.concrete_fields:
        if isinstance(field, models.FileField):
            try:
                instance_in_db = sender.objects.get(pk=instance.pk)
            except sender.DoesNotExist:
                return
                
            instance_in_db_file_field = getattr(instance_in_db, field.name)
            instance_file_field = getattr(instance, field.name)
            
            if instance_in_db_file_field.name != instance_file_field.name:
                delete_file_if_unused(sender, instance, field, instance_in_db_file_field)

def delete_file_if_unused(model, instance, field, instance_file_field):
    """Only delete the file if no other instances are using it"""
    if not instance_file_field.name:
        return
        
    dynamic_field = {}
    dynamic_field[field.name] = instance_file_field.name
    other_refs_exist = model.objects.filter(**dynamic_field).exclude(pk=instance.pk).exists()
    
    if not other_refs_exist and instance_file_field.name:
        instance_file_field.delete(False)
        
@receiver(post_save, sender=Student)
def update_student_count_on_save(sender, instance, created, **kwargs):
    """
    When a student is created, update the student count in the camp
    and all associated gallery items
    """
    if created:  # Only increment count on creation
        with transaction.atomic():
            # Update camp's total_students count
            camp = instance.camp
            camp.total_students = camp.students.count()
            camp.save(update_fields=['total_students'])
            
            # Update all gallery items for this camp
            Gallery.objects.filter(camp=camp).update(student_count=camp.total_students)

@receiver(post_delete, sender=Student)
def update_student_count_on_delete(sender, instance, **kwargs):
    """
    When a student is deleted, update the student count in the camp
    and all associated gallery items
    """
    try:
        with transaction.atomic():
            camp = instance.camp
            camp.total_students = camp.students.count()
            camp.save(update_fields=['total_students'])
            
            # Update all gallery items for this camp
            Gallery.objects.filter(camp=camp).update(student_count=camp.total_students)
    except Camp.DoesNotExist:
        # Camp was deleted, nothing to update
        pass