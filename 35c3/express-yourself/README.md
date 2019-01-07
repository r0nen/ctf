# Express yourself - 35C3 CTF 

**Category**: zajebiste (web)
**Points**: 500

This year I attended 35C3 conference so I didn't have time to actually participate in the CTF with my team 5BC. After the CTF was over, my colleague challenged me to solve the `express-yourself` challenge which apparently no one solved during the event. I like source code auditing so I accepted the challenge. 

(Beware - A lot of php code coming up...)

## Introduction

The challenge description:
```
I heard nowadays the cool kids like Donald J. Trump use ExpressionEngine to express themselves on the Internet. After all, the "Best CMS" is just about good enough for the bestest presidents.

This morning I set up a default install and gave it a try, do you like it?

PSA: dont dirbuster it... you won't find anything

Info: Here are a few deployment details: https://35c3ctf.ccc.ac/uploads/express_yourself_deployment_details.txt in case you got confused why the system directory might be missing.

Hint: flag is in db

Hint2: challenge was probably a bit miscategorized in the "web" category, it belongs into the zajebiste category. There are no hidden files or anything, see the deployment script. you can set up the same environment locally and pwn it. no need to bruteforce anything, good luck

```

So basically the task was to install ExpressEngine using the deployment script (Which "hardens" the setup), audit the source code, find vulnerabilities in the default setup to get the flag.

Before digging into the source code, I like to blackbox test the system. I usually open Burpsuite and navigate through the pages/features of the system. That way, I get the feeling of how large the initial attack surface is. In that stage/audit stage I take small notes of vulnerabilty classes/vectors that are likely to be found in the system. That way I can focus the research on this list.

Here are some of the notes I took during the research:
```
1. When sending feedback at the contact page, it sends "allow_attachments" parameter, maybe there is a way to upload attachments?
2. Expression Engine... maybe EL injection?
3. They are using controllers, Maybe LFI in controller inclusion? Also, search for autoload, and functions that can cause autoload, like class_exists and new $xxx. Also, there is a method called load_class which can load classes.
4. File read/xxe? PHAR -> unserialize?
5. SSRF?
6. SQL Injection? I will need to select the flag from the db, so either SQLi, file read to read the config and code execution?
7. __call functions can be interesting
8. _get_meta_vars leads to object injection if I could somehow leak the key...
```


# Understanding the system
Starting with understanding how the controllers work might give us insights into how the system is constructed. How can we use controllers? How can we invoke methods? and so on... Eventually, after some research, it appears that there are some potentially interesting controller methods, but how do we invoke them? Simple! REST API!

```
http://URL/index.php/[directory]/[controller]/[method]/[params]

Params can also be passed through $_GET/$_POST. 
```

But apparently, the root `index.php` contain the following lines:
```php
...
/*
 * ---------------------------------------------------------------
 *  Disable all routing, send everything to the frontend
 * ---------------------------------------------------------------
 */
	$routing['directory'] = '';
	$routing['controller'] = 'ee';
	$routing['function'] = 'index';
...
```

By default, the controller parsing is ignored and only the `index` method from the legacy controller `ee` can be called! What it contains? Let's dive in.

```php
class EE extends EE_Controller {

	/**
	 * Index
	 */
	function index()
	{
		...
		$can_view_system = ($this->session->userdata('group_id') == 1) ? TRUE : $can_view_system;

		if (REQ != 'ACTION' && $can_view_system != TRUE)
		{
			$this->output->system_off_msg();
			exit;
		}

		if (REQ == 'ACTION')
		{
			$this->core->generate_action($can_view_system);
		}
		elseif (REQ == 'PAGE')
		{
			$this->core->generate_page();
		}
		...
	}
}
```

Here is a short version of the `index` function. We can see that if `REQ` is equal to "ACTION", which means that the `ACT` parameter was supplied by `$_GET`/`$_POST`, then it calls `generate_action` function. Otherwise, it calls `generate_page`. The more interesting method is `generate_action`:

```php
final public function generate_action($can_view_system = FALSE)
{
	require APPPATH.'libraries/Actions.php';

	// @todo remove ridiculous dance when PHP 5.3 is no longer supported
	$that = $this;
	$ACT = new EE_Actions($can_view_system, function($class, $method) use ($that) {
		$that->set_newrelic_transaction('ACT: '.$class.'::'.$method.'()');
	});
}
```

We can see that this function instantiate the `EE_Actions` class. Let's see the constructor:
```php
public function __construct($can_view_system = FALSE, $callback = NULL)
{
	...
	if ( ! $action_id = ee()->input->get_post('ACT'))
	{
		return FALSE;
	}

	if (is_numeric($action_id))
	{
		ee()->db->select('class, method, csrf_exempt');
		ee()->db->where('action_id', $action_id);
		$query = ee()->db->get('actions');
		...

		$class  = ucfirst($query->row('class'));
		$method = strtolower($query->row('method'));
		$csrf_exempt = (bool) $query->row('csrf_exempt');
	}
	...
	if ($type == 'mcp')
	{
		$fqcn = $addon->getControlPanelClass();
	}
	else
	{
		$fqcn = $addon->getModuleClass();
	}

	// Instantiate the class/method
	$ACT = new $fqcn(0);

	$flags = 0;

	if ($method != '')
	{
		if ( ! is_callable(array($ACT, $method)))
		{
			...
		}

		if (is_callable($callback))
		{
			call_user_func($callback, $class, $method);
		}

		// Execution
		$ACT->$method();
	}
	...
}
```

If the `ACT` parameter was supplied, the function selects the `class` and `method` from the `actions` table by the supplied id. Later we can see the instantiation of the selected class and execution of the method. So what is our attack surface?
```
ID  Class      		Function
1 	Channel 		submit_entry
2 	Channel 		filemanager_endpoint
3 	Channel 		smiley_pop
4 	Channel 		combo_loader
5 	Comment 		insert_new_comment
6 	Comment_mcp 	delete_comment_notification
7 	Comment 		comment_subscribe
8 	Comment 		edit_comment
9 	Consent 		grantConsent
10 	Consent 		submitConsent
11 	Consent 		withdrawConsent
12 	Member 			registration_form
13 	Member 			register_member
14 	Member 			activate_member
15 	Member 			member_login
16 	Member 			member_logout
17 	Member 			send_reset_token
18 	Member 			process_reset_password
19 	Member 			send_member_email
20 	Member 			update_un_pw
21 	Member 			member_search
22 	Member 			member_delete
23 	Rte 			get_js
24 	Relationship 	entryList
25 	Search 			do_search
26 	Email 			send_email
```

We can focus the research on this list and start looking at each function.

# The solution
An interesting entry in the list is the `filemanager_endpoint`. What does it do? Why we can access this method unauthenticated? This function actually calls `process_request` from the `Filemanager` class, so let's look at this function:
```php
function process_request($config = array())
{
	$this->_initialize($config);
	$type = ee()->input->get('action');

	switch($type)
	{
		case 'setup':
			$this->setup();
			break;
		case 'setup_upload':
			$this->setup_upload();
			break;
		case 'directory':
			$this->directory(ee()->input->get('directory'), TRUE);
			break;
		case 'directories':
			$this->directories(TRUE);
			break;
		case 'directory_contents':
			$this->directory_contents();
			break;
		case 'directory_info':
			$this->directory_info();
			break;
		case 'file_info':
			$this->file_info();
			break;
		case 'upload':
			$this->upload_file(ee()->input->get_post('upload_dir'), FALSE, TRUE);
			break;
		case 'edit_image':
			$this->edit_image();
			break;
		case 'ajax_create_thumb':
			$this->ajax_create_thumb();
			break;
		default:
			exit('Invalid Request');
	}
}
```

This function does a lot! By supplying an `action` we can get into many flows, but let's focus now on the `directory_contents` flow. At the start of the `directory_contents` function it calls to the `datatables` function:

```php
public function datatables($first_dir = NULL)
{
	ee()->load->model('file_model');
	ee()->load->library('table');

	$per_page	= ee()->input->get_post('per_page');
	$dir_id 	= ee()->input->get_post('dir_choice');
	$keywords 	= ee()->input->get_post('keywords');
	$tbl_sort	= ee()->input->get_post('tbl_sort');

	// Default to file_name sorting if tbl_sort isn't set
	$state = (is_array($tbl_sort)) ? $tbl_sort : array('sort' => array('file_name' => 'asc'));

	$params = array(
		'per_page'	=> $per_page ? $per_page : 15,
		'dir_id'	=> $dir_id,
		'keywords'	=> $keywords
	);

	$data = ee()->table->datasource('_file_datasource', $state, $params);
	...
```

We can see that this function takes a lot of parameters from the user. One interesting parameter is `tbl_sort`. It looks like if it wasn't supplied, `$state` gets set to a default sorting. Otherwise, it sets as a user controlled sorting. Later, the above parameters get passed to the `ee()->table->datasource` function:

```php
function datasource($func, $options = array(), $params = array())
{
	$settings = array(
		'offset'		=> 0,
		'sort'			=> array(),		// column_name => value
		'columns'		=> $this->column_config
	);

	// override initial settings
	foreach (array_keys($settings) as $key)
	{
		if (isset($options[$key]))
		{
			$settings[$key] = $options[$key];
		}
	}

	...
	// override sort settings from POST (EE does not allow for arrays in GET)
	if (ee()->input->post('tbl_sort'))
	{
		$settings['sort'] = array();

		$sort = ee()->input->post('tbl_sort');

		// sort: [ [field, dir], [dleif, rid] ]
		foreach ($sort as $s)
		{
			$settings['sort'][ $s[0] ] = $s[1];
		}
	}

	$controller = isset(ee()->_mcp_reference) ? ee()->_mcp_reference : ee();
	$data = $controller->$func($settings, $params);
	...
	return $data;
}
```

The `$options` parameter overrides some of the settings. Below we can see a check for the `tbl_sort` parameter again. If it was supplied, it overrides the sort settings in the `settings` variable. This raises a big red flag:

```php
$settings['sort'][ $s[0] ] = $s[1];
```
A user controlled data can be set as the key of a sort. This can be a bad practice, because `sort` usually means SQL `order by`, and if we understand correctly we can probably influence the column name by which the order by occurs. Column names are sometimes not sanitized properly because they don't come from user input. So, next, the `$controller->$func` is being executed. `$func` is the `_file_datasource` function:

```php
public function _file_datasource($state, $params)
{
	...

	$file_params = array(
		'type'		=> $dir['allowed_types'],
		'order'		=> $state['sort'],
		'limit'		=> $per_page,
		'offset'	=> $state['offset']
	);
	...
	return array(
		'rows'			=> $this->_browser_get_files($dir, $file_params),
		...
	);
}
```

So our assumptions were correct. Indeed the `sort` parameter is used as order by. The `_browser_get_files` calls to the `ee()->file_model->get_files` function with the `$file_params` so let's see what it does:

```php
function get_files($dir_id = array(), $parameters = array())
{
	...
	$dir_id = ( ! is_array($dir_id)) ? array($dir_id) : $dir_id;

	if ( ! empty($dir_id))
	{
		$this->db->where_in("upload_location_id", $dir_id);
	}

	...
	if (isset($parameters['order']) && is_array($parameters['order']) && count($parameters['order']) > 0)
	{
		foreach ($parameters['order'] as $key => $val)
		{
			// If the key is set to upload location name, then we need to
			// join upload_prefs and sort on the name there
			if ($key == 'upload_location_name')
			{
				$this->db->join('upload_prefs', 'upload_prefs.id = files.upload_location_id');
				$this->db->order_by('upload_prefs.name', $val);
				continue;
			}

			$this->db->order_by('files.'.$key, $val);
		}
	}
	...

	$return_data['results'] = $this->db->get('files');

	$this->db->flush_cache();

	return $return_data;
}
```

Looks like the `get_files` function "constructs" an SQL query. We were interested in the "order by" flow. It loops through the `$parameters['order']` and if the `$key` is not equals "upload_location_name" it just calls `$this->db->order_by` function with the `$key` variable appended to the key, and the value. I will spare you the long function, but as we assumed it doesn't sanitize the key properly and we have an SQL injection vulnerability!

Here is a picture of the malicious request being sent to a local server (runs in debug mode):
![Sqli](indended.png)

You can clearly see the 'out of context' string. From here it's a trivial exploitation:

1. Get the list of databases and see that there is a database called "flag".
2. Get the tables from the flag database and see that there is a table called "flag".
3. "select flag from flag" and get the desired flag: `35c3_pl3ase_d0nt_pwn_tRump_wItH_th1s` :)



# The unintended solution

So... If you remember in the switch/case in the `process_request` function, there was an upload flow. Interesting...

```php
	case 'upload':
		$this->upload_file(ee()->input->get_post('upload_dir'), FALSE, TRUE);
		break;
```

The `upload_file` actually calls `_upload_file` ("upload_dir" is a directory id which we can easily get by calling to the directory function from the switch/case).

```php
private function _upload_file($dir, $field_name)
{
	// Upload the file

	$field = ($field_name) ? $field_name : 'userfile';
	$original_filename = $_FILES[$field]['name'];
	$clean_filename = basename($this->clean_filename(
		$_FILES[$field]['name'],
		$dir['id'],
		array('ignore_dupes' => TRUE)
	));

	$config = array(
		'file_name'		=> $clean_filename,
		'upload_path'	=> $dir['server_path'],
		'max_size'		=> round((int)$dir['max_size'], 3)
	);

	// Restricted upload directory?
	if ($dir['allowed_types'] == 'img')
	{
		$config['is_image'] = TRUE;
	}

	ee()->load->helper('xss');

	// Check to see if the file needs to be XSS Cleaned
	if (xss_check())
	{
		$config['xss_clean'] = TRUE;
	}

	// Upload the file
	ee()->load->library('upload');
	ee()->upload->initialize($config);

	if ( ! ee()->upload->do_upload($field_name))
	{
		return $this->_upload_error(
			ee()->upload->display_errors()
		);
	}
	...
}
```

So what this function does?
1. Cleans the name of the supplied file
2. Checks if the `allowed_type` equals "image"? In our case it is
3. Checks for XSS in the file content!?
4. Calls `do_upload` to upload the file..

```php
public function do_upload($field = 'userfile')
{
	// Is $_FILES[$field] set? If not, no reason to continue.
	if ( ! isset($_FILES[$field]))
	{
		$this->set_error('upload_no_file_selected');
		return FALSE;
	}
	...

	// Set the uploaded data as class variables
	$this->file_temp = $_FILES[$field]['tmp_name'];
	$this->file_size = $_FILES[$field]['size'];
	$this->file_type = ee()->mime_type->ofFile($this->file_temp);
	$this->file_name = $this->_prep_filename($_FILES[$field]['name']);
	$this->file_ext	 = $this->get_extension($this->file_name);
	$this->client_name = $this->file_name;

	// Is this a hidden file? Not allowed
	if (strncmp($this->file_name, '.', 1) == 0)
	{
		$this->set_error('upload_invalid_file');
		return FALSE;
	}

	$disallowed_names = ee()->config->item('upload_file_name_blacklist');
	...
	if (in_array(strtolower($this->file_name), $disallowed_names))
	{
		$this->set_error('upload_invalid_file');
		return FALSE;
	}

	// Is the file type allowed to be uploaded?
	if ( ! $this->is_allowed_filetype())
	{
		$this->set_error('upload_invalid_file');
		return FALSE;
	}

	// Sanitize the file name for security
	$this->file_name = $this->clean_file_name($this->file_name);

	...
	if ($this->is_image)
	{
		if ($this->do_embedded_php_check() === FALSE)
		{
			$this->set_error('upload_unable_to_write_file');
			return FALSE;
		}
	}

	if ( ! @copy($this->file_temp, $this->upload_path.$this->file_name))
	{
		if ( ! @move_uploaded_file($this->file_temp, $this->upload_path.$this->file_name))
		{
			$this->set_error('upload_destination_error');
			return FALSE;
		}
	}

	return TRUE;
}
```

Sorry for the long function... Let's explain what's going on:

1. First it sets some properties with values from the uploaded image
2. Checks for hidden files and disallowed file names like .htaccess
3. Checks for allowed file types. Firstly because our file has to be an image, it checks that our file is an actual image, but this can be bypassed by just uploading a valid image and appending extra content at the end. Next it checks the file extensions.. and this is where they use black list: `'php', 'php3', 'php4', 'php5', 'php7', 'phps', 'phtml'`.

    If you know the Apache web server php configuration well you probably can guess that they forgot to filter `.pht`, which also runs as PHP!
4. So the last step we have to bypass is the `do_embedded_php_check` check. They check if the file contains the `<?php` string. If it does, then they bail out. Otherwise, everything is ok. This can be easily bypassed by using a shortened version of a PHP code. For example `<?=echo '123';?>`

After all of those checks, the file is uploaded to the directory we chose by the directory_id parameter..

So all we need to do is:
1. Create an image with an appended PHP code
2. Upload it using the API with a name ending with '.pht'
3. Profit!?

So I had luck, and the CTF server was actually running Apache. I tried the exploit on it and it didn't work. The file just didn't execute as PHP... Something was wrong. The server was running the latest Ubuntu and I didn't, so I immediately installed a fresh copy and also installed the latest Apache server, PHP available. After checking the configuration I noticed that the regex responsible for catching PHP files changed, and `.pht` is not a valid extension anymore. However `.phar` was added to the list :O

So I quickly changed my exploit and you can see yourself.
![id](uindended.png)

The vendor actually pached the above vulnerabilities by just removing the access to the file manager :)
