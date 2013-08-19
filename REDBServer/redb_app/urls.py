from django.conf.urls import patterns, url

urlpatterns = patterns('',
    url(r'^$', 'redb_app.views.general_handler'),
)
