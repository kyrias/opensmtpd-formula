{% import 'opensmtpd/map.jinja' as opensmtpd -%}

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

{% for table, details in salt['pillar.get']('opensmtpd:tables').items() -%}
    {% if 'type' in details and 'contents' in details and details.type == 'file' -%}
table {{ table }}:
    file.managed:
        - name: {%
        if details.path.startswith('/') -%}
            {{ details.path }}
        {% else -%}
            {{ opensmtpd.configdir }}/{{ details.path }}
        {% endif -%}
        - contents: |
        {%- for line in details.contents %}
            {{ line }}
        {%- endfor %}
        - require_in:
            - file: smtpd.conf
        - watch_in:
            - service: opensmtpd
    {%- endif %}
{% endfor %}
