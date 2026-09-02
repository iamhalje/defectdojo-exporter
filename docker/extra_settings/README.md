# Extra settings

Any `local_settings.py` (or other settings override files) placed in this
directory is copied into `dojo/settings/` inside the DefectDojo containers on
startup, exactly like the `docker/extra_settings` directory in the official
[django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) repository.

This `README.md` itself is ignored by the containers.
