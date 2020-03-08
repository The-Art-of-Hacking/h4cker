#!/usr/bin/python
import requests, sys, json, copy, fileinput

TR_SESSION = requests.session()


def get_config():
    global config
    config={}
    #options
    config['threat_response_token_file']='TR-token.txt'

    #credentials
    config['threat_response_api_client_id']="<INSERT YOUR API CLIENT ID HERE>"
    config['threat_response_api_client_pass']="<INSERT YOUR API CLIENT PASSWORD HERE>"

    #server (modify only to select region)
    config['threat_response_server']="visibility.amp.cisco.com"
    # EU - config['threat_response_server']="visibility.eu.amp.cisco.com
    # APJ - config['threat_response_server']="visibility.apjc.amp.cisco.com

    #paths (should not need to be modified)
    config['threat_response_api_root']="iroh/"
    config['threat_response_token_path']="oauth2/token"
    config['threat_response_inspect_path']="iroh-inspect/inspect"
    config['threat_response_deliberate_path']="iroh-enrich/deliberate/observables"
    config['threat_response_observe_path']="iroh-enrich/observe/observables"

    #make some useful variables now
    config['TRroot']='https://'+config['threat_response_server']+'/'+config['threat_response_api_root']
    config['inspect_url'] = config['TRroot']+config['threat_response_inspect_path']
    config['token_url']=config['TRroot']+config['threat_response_token_path']
    config['deliberate_url'] = config['TRroot']+config['threat_response_deliberate_path']
    config['observe_url'] = config['TRroot']+config['threat_response_observe_path']


    return(config)

def TR_generate_token():
    ''' Generate a new access token and write it to disk'''

    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    payload = {'grant_type':'client_credentials'}

    response = requests.post(config['token_url'], headers=headers,
                         auth=(config['threat_response_api_client_id'],
                               config['threat_response_api_client_pass']),
                         data=payload)

    if TR_unauthorized(response):
        sys.exit('Unable to generate new token!\nCheck your CLIENT_ID and CLIENT_PASSWORD')

    response_json = response.json()
    access_token = response_json['access_token']

    with open(config['threat_response_token_file'], 'w') as token_file:
        token_file.write(access_token)
    return(access_token)

def TR_get_token():
    ''' Get the access token from disk, or from auth API
    '''
    for i in range(2):
        while True:
            try:
                with open(config['threat_response_token_file'], 'r') as token_file:
                    access_token = token_file.read()
                    return access_token
            except FileNotFoundError:
                return TR_generate_token()
            break    

def TR_unauthorized(response):
    ''' Check the status code of the response
    '''
    if response.status_code == 401:
        return True
    return False

def TR_check_auth(function, param):
    ''' Query the API and validate authentication was successful
        If authentication fails, generate a new token and try again
    '''
    response = function(param)
    if TR_unauthorized(response):
        print('Auth failed, generating new token.')
        config['access_token']=TR_generate_token()
        return function(param)
    return response


def TR_query(text_block):
    ''' Pass the functions and parameters to check_auth to query the API
        Return the final response
    '''
    response = TR_check_auth(TR_inspect, text_block)
    inspect_output = response.text
    response = TR_check_auth(TR_enrich, inspect_output)  # TR_enrich() is undefined
    return response

def TR_inspect(text_block):
    '''Inspect the provided text block and extract observables
    '''

    headers = {'Authorization':'Bearer {}'.format(config['access_token']),
               'Content-Type':'application/json',
               'Accept':'application/json'}

    inspect_payload = {'content':text_block}
    inspect_payload = json.dumps(inspect_payload)

    response = TR_SESSION.post(config['inspect_url'], headers=headers, data=inspect_payload)
    return response

def TR_deliberate(observables):
    ''' Query the deliberate API for observable(s)
    '''
    headers = {'Authorization':'Bearer {}'.format(config['access_token']),
               'Content-Type':'application/json',
               'Accept':'application/json'}
    response = TR_SESSION.post(config['deliberate_url'], headers=headers, data=json.dumps(observables))
    return response

def TR_observe(observables):
    ''' Query the deliberate API for observable(s)
    '''
    headers = {'Authorization':'Bearer {}'.format(config['access_token']),
               'Content-Type':'application/json',
               'Accept':'application/json'}
    response = TR_SESSION.post(config['observe_url'], headers=headers, data=json.dumps(observables))
    return response

def uniq_observables(observables):
    uniqd=[]
    for obs in observables:
        if obs not in uniqd:
            uniqd.append(obs)
    return(uniqd)

def filter_cleans(results):
    cleans = [] #init list of observables with any clean verdict
    for obs in results: #loop through observables
        if 'verdicts' in obs: #if it has verdicts
            for verdict in obs['verdicts']: #loop through verdicts
                if verdict['verdict'] == "Clean": #if this one is clean
                    cleans.append(obs) # add the observable to list of cleans
                    break #and exit, since it takes only one 'clean' and we found one
    for obs in cleans: #go through our list
        results.remove(obs) #and for each entry, remove it from the initial dataset
    return(results) #return what's left

def main():

    #collect settings dict
    get_config()
    # get the token to use to start
    config['access_token']=TR_get_token()

    # process input
    # init some vars
    [text_chunk,observables, judgements, sightings]=['',[],[],[]]
    line_idx=0
    #chunking loop
    for line in fileinput.input():
         line_idx=line_idx+1
         text_chunk=text_chunk+line
         if len(text_chunk) > 2000: #if we hit the 2000 char max guideline, send the chunk for inspection
            these_observables = json.loads(TR_check_auth(TR_inspect,text_chunk).text)
            #append results to existing data
            observables=observables+these_observables
            # clear the chunk for reuse
            text_chunk=''

    #if we're here, we ran out of lines
    #inspect the last chunk if it has content
    if text_chunk != '':
        these_observables = json.loads(TR_check_auth(TR_inspect,text_chunk).text)
        #append results to existing data
        observables=observables+these_observables
    #uniq our observables
    observables= uniq_observables(observables)

    if len(observables) >50: # semi-arbitrary limit for performance reasons.
        # This is a cop-out. We could break the enrichment process into segments the same way we did the Inspection process
        # for this example, we'll keep it simple.   
        sys.exit('NOT doing enrichment! {} is too many observables. Break that input up.'.format(len(observables)))

    # init results data structure
    results = copy.deepcopy(observables)

    # Deliberate
    deliberations=json.loads(TR_check_auth(TR_deliberate,observables).text)
    for module_results in deliberations['data']:
        #add deliberations to results
        if 'verdicts' in module_results['data']:
            for verdict in module_results['data']['verdicts']['docs']: #loop through the verdicts in this module's output
                try:
                    for obs in results: #loop through our list of observables
                        if obs['value'] == verdict['observable']['value'] and obs['type'] == verdict['observable']['type']: #if this observable is the same as the one for the current verdict
                            this_verdict= {'module_name': module_results['module'], 'verdict': verdict['disposition_name'] }
                            if 'verdicts' not in obs: #if this is the first verdict on this observable,
                                obs['verdicts']=[] # then make a new blank list of verdicts
                            obs['verdicts'].append(this_verdict)
                            break
                except Exception as e:
                    print('{}:{}'.format(str(e)), json.dumps(obs, indent=4))

    #filter out anything with any "Clean" verdict
    results=filter_cleans(results)

    # Observe

    observations=json.loads(TR_check_auth(TR_observe,observables).text)#make the observe API call
    for observation in observations['data']:#parse the results one observation at a time; actually each module's output at a time
       if 'sightings' in observation['data']:#if it had any sightings
            for sighting in observation['data']['sightings']['docs']:#go through those sightings
                if 'targets' in sighting: # we are only interested in sightings with targets
                    for sighted_observable in sighting['observables']:#for each observable that was sighted
                        for obs in results:# look at each observable in our initial list
                            if obs['value'] == sighted_observable['value'] and obs['type'] == sighted_observable['type']: #if this observable is the same as the one for the current verdict
                                this_sighting= {'module_name': sighting['source'], 'sighting_count': sighting['count']} #create a new data element in our results set for this sighting
                                if 'sightings' not in obs: #if this is the first sighting on this observable,
                                    obs['sightings']=[] # then make a new blank list of sightings
                                obs['sightings'].append(this_sighting) # add this sighting to the list for this observable
                                break #found our match in a uniq'd list; no need to continue


    #summarizing/aggregating
    for item in results:
        #aggregate verdicts
        item['verdicts_count']=0 #init counter
        item['verdicts_module_list']=[] #init list of modules
        if 'verdicts' in item: #if there are verdicts
           for verdict in item['verdicts']: #for each one
               item['verdicts_count']=item['verdicts_count']+1 #increment counter
               item['verdicts_module_list'].append(verdict['module_name']) #add modulename to list
           item['verdicts_module_list']=list(set(item['verdicts_module_list'])) #when done, uniq list of modules

        #aggregate sightings
        item['sightings_count']=0#init counter
        item['sightings_module_list']=[]#init list of modules
        if 'sightings' in item: #if there are sightings
            for sighting in item['sightings']:#for each one
                    item['sightings_count']=item['sightings_count']+sighting['sighting_count']#increment counter
                    item['sightings_module_list'].append(sighting['module_name'])#add modulename to list
            item['sightings_module_list']=list(set(item['sightings_module_list']))#when done, uniq list of modules

    #filter out unseen observables
    results[:]= [item for item in results if item['sightings_count'] > 0] #make new list using only elements where there is at least one sighting

    if len(results)>0: #if there are 1+ entries left in the list of results
        print('the following observables were found in the input and were seen in your environment:')
        url='https://{}/#/investigate?q='.format(config['threat_response_server'])#init url
        for item in results: #for each remaining observable
            print('{} ({}): {} sightings, {} verdicts'.format(item['value'],item['type'],item['sightings_count'],item['verdicts_count'])) #print the sumamry information
            url=url+'{}%3A{}%0A'.format(item['type'], item['value']) #and add it to the CTR URL for an investigation
        print('To get more information and investigate these observables in Threat Response, go to the following location:')
        print(url)


if __name__ == '__main__':
    main()
