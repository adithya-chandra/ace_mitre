import yaml
import os
import sys
import json
from collections import defaultdict

def extract_mitre_ids(dir_path):
    tactics = []
    ctactics = 0
    techniques = defaultdict(list)
    total_files = 0
    files_with_attacks = 0
    files_without_attacks = 0
    file_stats = []
    ids_with_attacks = []
    ids_without_attacks = []

    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if file == "rule.yaml":
                total_files += 1
                file_path = os.path.join(root, file)
                with open(file_path,'r') as yaml_file:
                         data = yaml.safe_load(yaml_file)

                file_id = data.get('id','No ID')
    
                if 'metadata' in data and 'attacks' in data['metadata']:
                    files_with_attacks += 1
                    ids_with_attacks.append(file_id)
                    for attack in data['metadata']['attacks']:

                        #Tactics
                        if 'tactics' in attack:
                            #
                            for tactic in attack['tactics']:
                                tactic_entry = f"{tactic.get('name','Unknown')} (UID: {tactic.get('uid', 'Unknown')})"
                                if tactic_entry not in tactics:
                                    ctactics +=1
                                    tactics.append(tactic_entry)



                        #Technniques
                        if 'technique' in attack:
                                technique = attack['technique']
                                technique_id = technique.get('uid','Unknown')
                                techniques[technique_id].append(file_id)
                else:
                    files_without_attacks += 1
                    ids_without_attacks.append(file_id)

                file_stats.append({"file_path": file_path,
                                   "id": file_id,
                                   "has_attacks": 'Yes' if 'metadata' in data and 'attacks' in data['metadata'] else 'No'})

    return total_files, files_with_attacks, files_without_attacks, tactics, ctactics, techniques,file_stats, ids_with_attacks, ids_without_attacks

def calculate_color(score, max_value):
    if score == max_value:
        return "#8ec843" #green
    elif score >= max_value * 0.60:
        return "#edf777" #yellow
    elif score >= max_value * 0.40:
        return "#ffa500" #orange
    else:
        return "#ff6666" #red

def nav_json(techniques, output_file="ace_mitre_nav.json"):
    max_value = max(len(file_ids) for file_ids in techniques.values()) if techniques else 0
    nav_tech = []
    for technique_id, file_ids in techniques.items():
        score = len(file_ids)
        color = calculate_color(score, max_value) 
        nav_tech.append({
            "techniqueID": technique_id,
            "score": score,
            "comment":f"Rule ID's: {', '.join(file_ids)}",
            "enabled": True,
            "color": color
            }) 
    nav_data = {
        "name": "ACE Rules MITRE Heatmap",
        "versions":{
            "attack" : "16",
            "navigator": "4.4.4",
            "layer": "4.5"
        },

        "layout": {
        "layout": "side",
        "showName": True,
        "showID": False,
        "showAggregateScores": True,
        "countUnscored": True,
        "aggregateFunction": "average",
        },
        "domain":"mitre-enterprise",
        "description":"ACE mitre heatmap",
        "sorting" : 0,
        "viewMode": 0,
        "hideDisabled": False,
        "techniques": nav_tech,
        "gradient": {
            "colors": [
                "#ff6666",
                "#ffa500",
                "#edf777",
                "#8ec843"
            ],
            "maxValue": max_value,
            "minValue": 0
        },
        "legendItems": []
    }

    with open(output_file, "w") as json_file:
        json.dump(nav_data,json_file, indent=4)
    print(f"[*] MITRE Version:- v16", "\n[*] Navigator version:- 4.4.4")
    print(f"[*] JSON file written, please upload it to MITRE Navigator:- {output_file}")

if __name__ == '__main__':
    args = sys.argv[1:]

    if "-h" in args or "--help" in args:
        print("""
        Usage: python3 ace_mitre.py [options]

        Options:
            summary - A quick overview of rule files
            stats - Detailed overview of rule files
            tac   - Display Tactic IDs
            tec   - Display Technique IDs
            nav   - Generate Mitre Navigator JSON
            -h, --help   - Display this help message
            """)
        sys.exit(0)

    valid_args = {"summary","stats","tac","tec","nav","-h","--help"}
    invalid_args = [arg for arg in args if arg not in valid_args]
    if invalid_args:
        print(f"Oops! Invalid Args, please use -h or --help")
        sys.exit(1)

    if not args:
        print("Please provide atleast one argument, use -h or --help")
        sys.exit(1)

    dir_path = input("Enter Rules Directory: ")
    
    if not os.path.isdir(dir_path):
        print("Oops! Invalid path")
        sys.exit(1)

    total_files, files_with_attacks, files_without_attacks, tactics, ctactics, techniques,file_stats,ids_with_attacks, ids_without_attacks = extract_mitre_ids(dir_path)
    
    if "summary" in args:
        print(f"Total Rules: {total_files}")
        print(f"Rules with mitre data: {files_with_attacks}")
        print(f"Files without mitre data: {files_without_attacks}") 
    if "tac" in args:
        print("Total Tactics: ", ctactics)   
        print("Tactics:", ", ".join(tactics))
    if "tec" in args:
        print("Techniques:", ", ".join(techniques))

    if "stats" in args:
        print("\nFile Stats:")
        print("\nRules with mitre data:", ", ".join(ids_with_attacks) if ids_with_attacks else "None Found")
        print("\nRules without mitre data:", ", ".join(ids_without_attacks) if ids_without_attacks else "None Found")
    if "nav" in args:
        nav_json(techniques)