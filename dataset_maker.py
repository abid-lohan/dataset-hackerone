import requests
import json

output = []
API_URL = 'https://hackerone.com/graphql'
HEADERS = {'Content-Type': 'application/json'}

for page in range(0,10000,100):
    payload = {
        "operationName": "CompleteHacktivitySearchQuery",
        "variables": {
            "userPrompt": None,
            "queryString": "disclosed:true",
            "size": 100,
            "from": page,
            "sort": {
                "field": "latest_disclosable_activity_at",
                "direction": "DESC"
            },
            "product_area": "hacktivity",
            "product_feature": "overview"
        },
        "query": """
        query CompleteHacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {
        me {
            id
            __typename
        }
        search(
            index: CompleteHacktivityReportIndexService
            query_string: $queryString
            from: $from
            size: $size
            sort: $sort
        ) {
            __typename
            total_count
            nodes {
            __typename
            ... on CompleteHacktivityReportDocument {
                id
                _id
                reporter {
                id
                name
                username
                ...UserLinkWithMiniProfile
                __typename
                }
                cve_ids
                cwe
                severity_rating
                upvoted: upvoted_by_current_user
                public
                report {
                id
                databaseId: _id
                title
                substate
                url
                disclosed_at
                report_generated_content {
                    id
                    hacktivity_summary
                    __typename
                }
                __typename
                }
                votes
                team {
                handle
                name
                medium_profile_picture: profile_picture(size: medium)
                url
                id
                currency
                ...TeamLinkWithMiniProfile
                __typename
                }
                total_awarded_amount
                latest_disclosable_action
                latest_disclosable_activity_at
                submitted_at
                disclosed
                has_collaboration
                __typename
            }
            }
        }
        }

        fragment UserLinkWithMiniProfile on User {
        id
        username
        __typename
        }

        fragment TeamLinkWithMiniProfile on Team {
        id
        handle
        name
        __typename
        }
        """
    }

    res = requests.post(API_URL, json=payload, headers=HEADERS)
    nodes = res.json()['data']['search']['nodes']

    for node in nodes:
        output.append(node)

print(f"Tamanho do dataset: {len(output)}")

try:
    with open('dataset.json', 'w', encoding='utf-8') as file:
        json.dump(output, file, ensure_ascii=False, indent=4)
except:
    print("Falha ao criar o arquivo com o dataset.")

print("Arquivo dataset.json criado com sucesso!")