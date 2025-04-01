import os
from django.core.management.base import BaseCommand
from django.core.files import File
from api.models import Gallery
from django.conf import settings
from datetime import datetime

class Command(BaseCommand):
    help = 'Populates the gallery with sample images'

    def handle(self, *args, **kwargs):
        # Clear existing gallery items
        Gallery.objects.all().delete()
        self.stdout.write('Deleted existing gallery items')

        # Define locations and their corresponding images
        locations = {
            'Salkot': [
                {'filename': 'salkot_1.png', 'type': 'regularclasses'},
                {'filename': 'salkot_2.png', 'type': 'doubts'},
                {'filename': 'salkot_3.png', 'type': 'exams'},
            ],
            'Narayan Bagar': [
                {'filename': 'narayan_bagar_1.png', 'type': 'regularclasses'},
                {'filename': 'narayan_bagar_2.png', 'type': 'doubts'},
                {'filename': 'narayan_bagar_3.png', 'type': 'exams'},
            ],
            'GMS': [
                {'filename': 'GMS2.jpeg', 'type': 'regularclasses'},
                {'filename': 'Logo.png', 'type': 'doubts'},
            ]
        }

        # Create gallery items for each location
        for location, images in locations.items():
            for image_info in images:
                image_path = os.path.join(settings.MEDIA_ROOT, 'gallery', image_info['filename'])
                if os.path.exists(image_path):
                    with open(image_path, 'rb') as f:
                        gallery_item = Gallery.objects.create(
                            title=f"{location} - {image_info['type'].replace('_', ' ').title()}",
                            location=location,
                            type=image_info['type'],
                            description=f"Sample {image_info['type'].replace('_', ' ')} image from {location}",
                            date=datetime.now().date(),
                            year=2024
                        )
                        gallery_item.image.save(image_info['filename'], File(f), save=True)
                        self.stdout.write(f'Created gallery image: {gallery_item.title}')
                else:
                    self.stdout.write(self.style.WARNING(f'Image not found: {image_path}'))

        self.stdout.write(self.style.SUCCESS('Successfully populated gallery with sample images')) 