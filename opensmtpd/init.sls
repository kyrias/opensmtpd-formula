{% from 'opensmtpd/map.jinja' import opensmtpd -%}
{% import 'opensmtpd/defaults.yaml' as defaults -%}
opensmtpd:
    pkg:
        - installed
{%- if opensmtpd.pkg != 'opensmtpd' %}
        - name: {{ opensmtpd.pkg }}
{%- endif %}
    service.running:
{%- if opensmtpd.service != 'opensmtpd' %}
        - name: {{ opensmtpd.service }}
{%- endif %}
        - enable: True
        - require:
            - file: smtpd.conf
        - watch:
            - file: smtpd.conf

opensmtpd_configdir:
    file.directory:
        - name: {{ opensmtpd.configdir }}
        - user: root
        - group: root
        - mode: 755

smtpd.conf:
    file.managed:
        - name: {{ opensmtpd.configdir }}/smtpd.conf
        - source: salt://opensmtpd/files/smtpd.py
        - template: py
        - mode: 644
        - require:
            - pkg: opensmtpd
            - file: opensmtpd_configdir

{% if salt['pillar.get']('opensmtpd:mailname', False) -%}
mailname:
    file.managed:
        - name: {{ opensmtpd.configdir }}/mailname
        - contents_pillar: opensmtpd:mailname
        - required_in:
            - service: opensmtpd
{% endif -%}
