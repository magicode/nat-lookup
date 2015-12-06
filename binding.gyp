{  
'variables': {
   },
  "targets": [
    {
        "target_name": "natlookup",
        "sources": [ 
            'nat-lookup.cc'
        ],
        'include_dirs': [
	  "<!(node -e \"require('nan')\")"
	]
    }
    
  ]
}

