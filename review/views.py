from django.shortcuts import render, redirect
from .forms import ConfigUploadForm
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def index(request):
    return redirect('upload_config')

@csrf_exempt
def upload_config(request):
    if request.method == 'POST':
        form = ConfigUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['config_file']
            system_type = form.cleaned_data['system_type']
            lines = file.read().decode('utf-8', errors='ignore').splitlines()

            from .checkers import (
                fortinet_firewall_checker,
                paloalto_checker,
                cisco_firewall_checker,
                juniper_firewall_checker,
                checkpoint_checker,
                sophos_checker,
                cisco_switch_checker,
                juniper_switch_checker,
                aruba_switch_checker,
                extreme_switch_checker,
                cisco_router_checker,
                juniper_router_checker,
                windows10_checker,
                windows11_checker,
                windows_server_2019_checker,
                windows_server_2022_checker,
                debian_checker,
                rhel_checker,
                suse_checker,
            )

            checker_map = {
                'fortinet': fortinet_firewall_checker,
                'paloalto': paloalto_checker,
                'cisco_firewall': cisco_firewall_checker,
                'juniper_firewall': juniper_firewall_checker,
                'checkpoint': checkpoint_checker,
                'sophos': sophos_checker,
                'cisco_switch': cisco_switch_checker,
                'juniper_switch': juniper_switch_checker,
                'aruba_switch': aruba_switch_checker,
                'extreme_switch': extreme_switch_checker,
                'cisco_router': cisco_router_checker,
                'juniper_router': juniper_router_checker,
                'windows10': windows10_checker,
                'windows11': windows11_checker,
                'windows_server_2019': windows_server_2019_checker,
                'windows_server_2022': windows_server_2022_checker,
                'debian' : debian_checker,
                'rhel' : rhel_checker,
                'suse' : suse_checker
            }

            if system_type in checker_map:
                results = checker_map[system_type].check_rules(lines)
                request.session['review_results'] = results
                return redirect('review_result')
            else:
                return render(request, 'review/upload.html', {
                    'form': form,
                    'error': 'Unsupported system type selected.'
                })
    else:
        form = ConfigUploadForm()

    return render(request, 'review/upload.html', {'form': form})


@csrf_exempt
def review_result(request):
    results = request.session.get('review_results', [])

    # Calculate counts
    total = len(results)
    count_pass = sum(1 for _, status, _ in results if status == "Pass")
    count_fail = sum(1 for _, status, _ in results if status == "Fail")
    count_missing = sum(1 for _, status, _ in results if status == "Missing")
    count_unknown = sum(1 for _, status, _ in results if status in ("Unknown", "Unrecognized"))

    # Calculate percentages safely
    if total > 0:
        pct_pass = round(count_pass / total * 100, 2)
        pct_fail = round(count_fail / total * 100, 2)
        pct_missing = round(count_missing / total * 100, 2)
        pct_unknown = round(count_unknown / total * 100, 2)
    else:
        pct_pass = pct_fail = pct_missing = pct_unknown = 0

    context = {
        'results': results,
        'total': total,
        'count_pass': count_pass,
        'count_fail': count_fail,
        'count_missing': count_missing,
        'count_unknown': count_unknown,
        'chart_data': {
            'Pass': count_pass,
            'Fail': count_fail,
            'Missing': count_missing,
            'Unknown': count_unknown
        }
    }
    return render(request, 'review/result.html', context)
