from django import forms

class ConfigUploadForm(forms.Form):
    system_type = forms.ChoiceField(
        choices=[
            ('Firewalls', [
                ('fortinet', 'Fortinet'),
                ('paloalto', 'Palo Alto'),
                ('cisco_firewall', 'Cisco'),
                ('juniper_firewall', 'Juniper'),
                ('checkpoint', 'Check Point'),
                ('sophos', 'Sophos'),
            ]),
            ('Switches', [
                ('cisco_switch', 'Cisco'),
                ('juniper_switch', 'Juniper'),
                ('aruba_switch', 'Aruba'),
                ('extreme_switch', 'Extreme Networks'),
            ]),
            ('Routers', [
                ('cisco_router', 'Cisco'),
                ('juniper_router', 'Juniper'),
            ]),
            ('Operating Systems', [
                ('windows10', 'Windows 10'),
                ('windows11', 'Windows 11'),
                ('windows_server_2019', 'Windows Server 2019'),
                ('windows_server_2022', 'Windows Server 2022'),
            ]),
            ('Linux', [
                ('debian', 'Debian'),
                ('rhel', 'Rhel'),
                ('suse', 'Suse'),
            ])
        ],
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    config_file = forms.FileField(
        widget=forms.ClearableFileInput(attrs={'class': 'form-control'})
    )
