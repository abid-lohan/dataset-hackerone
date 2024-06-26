import json

def name_treatment(vuln):
    if vuln != None:
        if ' - Generic' in vuln:
            vuln = vuln.replace(' - Generic', '')

        if 'Cross-site Scripting' in vuln or 'XSS' in vuln:
            return 'Cross-site Scripting (XSS)'
        
        elif 'Path Traversal' in vuln:
            return 'Path Traversal'
        
        else:
            return vuln

def get_vuln_data(dataset):
    vulns = {}

    for node in dataset:
        cwe = name_treatment(node['cwe'])

        if cwe in vulns:
            vulns[cwe]['findings'] += 1
            vulns[cwe]['votes'] += node['votes']

            if node['total_awarded_amount'] != None:
                vulns[cwe]['mean_amounts'] = ((vulns[cwe]['findings'] - 1) * vulns[cwe]['mean_amounts'] + node['total_awarded_amount']) / vulns[cwe]['findings']

            else:
                vulns[cwe]['not_payed'] += 1

        else:
            vulns[cwe] = {'findings': 1, 'mean_amounts': 0, 'not_payed': 0, 'votes': 0}

            if node['total_awarded_amount'] != None:
                vulns[cwe]['mean_amounts'] = node['total_awarded_amount']
            
            else:
                vulns[cwe]['not_payed'] = 1
    
    vulns.pop(None, None) # Removing 1148 non categorized vulnerabilities

    return vulns

def get_autor_data(dataset):
    autors = {}

    for node in dataset:
        if node['reporter'] != None:
            autor = node['reporter']['username']
        else:
            autor = None

        if autor in autors:
            autors[autor]['findings'] += 1
            autors[autor]['votes'] += node['votes']

            if node['total_awarded_amount'] != None:
                autors[autor]['mean_amounts'] = ((autors[autor]['findings'] - 1) * autors[autor]['mean_amounts'] + node['total_awarded_amount']) / autors[autor]['findings']

            else:
                autors[autor]['not_payed'] += 1

        else:
            autors[autor] = {'findings': 1, 'mean_amounts': 0, 'not_payed': 0, 'votes': 0}

            if node['total_awarded_amount'] != None:
                autors[autor]['mean_amounts'] = node['total_awarded_amount']
            
            else:
                autors[autor]['not_payed'] = 1
    
    autors.pop(None, None) # Removing null autors

    return autors

def print_top10(ordered_list):
    for i, (autor, value) in enumerate(ordered_list.items()):
        if i < 10:
            print(f"{autor}: {value}")
        else:
            break

def print_all_results(vuln_data, autor_data):
    most_popular_vulns = dict(sorted(vuln_data.items(), key=lambda item: item[1]['findings'], reverse=True))
    most_payed_vulns = dict(sorted(vuln_data.items(), key=lambda item: item[1]['mean_amounts'], reverse=True))
    most_voted_vulns = dict(sorted(vuln_data.items(), key=lambda item: item[1]['votes']/item[1]['findings'], reverse=True))

    print("Top 10 vulnerabilidades com mais achados:")
    print_top10(most_popular_vulns)
    print("\nTop 10 vulnerabilidades mais bem pagas em média:")
    print_top10(most_payed_vulns)
    print("\nTop 10 vulnerabilidades mais bem votadas em média:")
    print_top10(most_voted_vulns)

    most_finds_autors = dict(sorted(autor_data.items(), key=lambda item: item[1]['findings'], reverse=True))
    most_payed_autors = dict(sorted(autor_data.items(), key=lambda item: item[1]['mean_amounts'], reverse=True))
    most_voted_autors = dict(sorted(autor_data.items(), key=lambda item: item[1]['votes'], reverse=True))

    print("\n\nTop 10 autores com mais achados:")
    print_top10(most_finds_autors)
    print("\nTop 10 autores mais bem pagos:")
    print_top10(most_payed_autors)
    print("\nTop 10 autores mais bem votados:")
    print_top10(most_voted_autors)


file = open("dataset.json", "r")
dataset = json.loads(file.read())

vuln_data = get_vuln_data(dataset)
autor_data = get_autor_data(dataset)

print_all_results(vuln_data, autor_data)

file.close()