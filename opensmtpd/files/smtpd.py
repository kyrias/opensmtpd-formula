#!py

import json

def generate_pkis(defaults):
    lines = []
    pkis = __salt__['pillar.get']('opensmtpd:pki')
    if not pkis:
        pkis = defaults['pki']

    for host, details in pkis.items():
        for key, value in details.items():
            lines.append('pki {} {} "{}"'.format(host, key, value))

    lines.append('')
    return lines


def generate_tables(defaults):
    lines = []
    tables = __salt__['pillar.get']('opensmtpd:tables')
    if not tables:
        tables = defaults['tables']

    for table, details in tables.items():
        line = 'table {}'.format(table)
        if 'type' in details and details['type'] != 'inline':
            line += ' {}:'.format(details['type'])
            if details['path'].startswith('/'):
                line += details['path']
            else:
                line += '{}/{}'.format('/etc/smtpd', details['path'])

        lines.append(line)

    lines.append('')
    return lines


def generate_listeners(defaults):
    lines = []
    listeners = __salt__['pillar.get']('opensmtpd:listeners')
    if not listeners:
        listeners = defaults['listeners']

    for listen in listeners:
        line = ''
        if 'interface' in listen:
            line += 'listen on {}'.format(listen['interface'])
        else:
            line += 'listen on socket'

        if 'family' in listen:
            line += '  {}'.format(listen['family'])

        if 'port' in listen:
            line += '  port {}'.format(listen['port'])

        if 'filter' in listen:
            line += '  filter {}'.format(listen['filter'])

        if listen.get('tls'):
            line += '  tls'

        if listen.get('tls-require'):
            if isinstance(listen['tls-require'], bool):
                line += '  tls-require'
            else:
                line += '  tls-require {}'.format(listen['tls-require'])

        if listen.get('smtps'):
            line += '  smtps'

        if listen.get('secure'):
            line += '  secure'

        if 'pki' in listen:
            line += '  pki {}'.format(listen['pki'])

        if 'ca' in listen:
            line += '  ca {}'.format(listen['ca'])

        if listen.get('auth'):
            if isinstance(listen['auth'], bool):
                line += '  auth'
            else:
                line += '  auth {}'.format(listen['auth'])

        if listen.get('auth-optional'):
            if isinstance(listen['auth-optional'], bool):
                line += '  auth-optional '
            else:
                line += '  auth-optional {}'.format(listen['auth-optional'])

        if 'tag' in listen:
            line += '  tag {}'.format(listen['tag'])

        if 'hostname' in listen:
            line += '  hostname {}'.format(listen['hostname'])

        if 'senders' in listen:
            line += '  senders {}'.format(listen['senders'])

        if listen.get('mask-source'):
            line += '  mask-source '

        if listen.get('received-auth'):
            line += '  received-auth '

        if listen.get('no-dsn'):
            line += '  no-dsn'

        lines.append(line)

    lines.append('')
    return lines


def generate_rules(defaults):
    lines = []
    rules = __salt__['pillar.get']('opensmtpd:rules')
    if not rules:
        rules = defaults['rules']

    for rule in rules:
        for _, details in rule.items():
            line = ''
            if details.get('type') == 'accept':
                line += 'accept'
            elif details.get('type') == 'reject':
                line += 'reject'
            else:
                raise Exception("Something borked")

            if details.get('tagged'):
                line += '  tagged {}'.format(details['tagged'])

            if details.get('from'):
                line += '  from {}'.format(details['from'])

            if details.get('sender'):
                line += '  sender {}'.format(details['sender'])

            if details.get('for'):
                line += '  for {}'.format(details['for'])

            if details.get('recipient'):
                line += '  recipient {}'.format(details['recipient'])

            if details.get('userbase'):
                line += '  userbase {}'.format(details['userbase'])

            if details.get('forward-only'):
                line += '  forward-only'

            if details.get('deliver_to'):
                line += '  deliver to {}'.format(details['deliver_to'])

            if details.get('relay'):
                if isinstance(details['relay'], bool):
                    line += '  relay'
                else:
                    line += '  relay {}'.format(details['relay'])

            if details.get('relay_via'):
                line += '  relay via {}'.format(details['relay_via'])

            if details.get('expire'):
                line += '  expire {}'.format(details['expire'])

            lines.append(line)

    lines.append('')
    return lines

def run():
    __salt__._load_all()
    raise Exception(list(__salt__))
    lines = []
    lines.extend(generate_pkis(defaults))
    lines.extend(generate_tables(defaults))
    lines.extend(generate_listeners(defaults))
    lines.extend(generate_rules(defaults))
    return '\n'.join(lines)
