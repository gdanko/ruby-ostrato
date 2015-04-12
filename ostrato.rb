require "net/https"
require "json"
require "pp"
require "etc"
require "securerandom"

class Ostrato
	attr_accessor :_success
	attr_accessor :_output
	attr_accessor :_count
	attr_accessor :_errors
	attr_accessor :_debug
	attr_accessor :_urls
	attr_accessor :_token
	attr_accessor :proxy
	attr_accessor :base_url
	attr_accessor :providers

	def initialize(opts)
		self._urls = Array.new
		self._errors = Array.new
		self.base_url = "https://demo3.ostrato.com/dashboard"

		self._error_exit("you must specify your username.") unless opts["user"]
		self._error_exit("you must specift your password.") unless opts["pass"]
		self.auth({"user" => opts["user"], "pass" => opts["pass"]})
		if (self.success)
			self._token = self.output["token"]
		else
			self._error_exit(self.errors)
		end

		self.providers = {
			"aws" => 1,
			"rackspace" => 2,
			"openstack" => 3,
			"azure" => 4,
			"vsphere" => 5,
			"softlayer" => 7
		}
	end

	def debug(flag)
		return unless flag
		if (flag == "on")
			flag = "on"
		else
			flag = "off"
		end
		self._debug = flag
	end

	def success
		return self._success || nil
	end

	def count
		return self._count || 0
	end

	def last_url
		return self._urls[ self._urls.length - 1] || nil
	end

	def output
		return self._output
	end

	def errors
		return self._errors.join("; ") || nil
	end

	def _debug_text(text)
		return unless self._debug == "on"
		puts("[Debug] #{text}")
	end

	def _error_exit(text)
		puts("[Error] #{text}")
		exit
	end

	def _warn_text(text)
		puts("[Warn] #{text}")
	end

	def _validate_json(string)
		hashref = JSON.parse(string)
		return hashref
	rescue JSON::ParserError
		return nil
	end

	def _group_id(name)
		return self._id(name, "groups?hierarchy=1", "name", "id")
	end

	def _auth_settings_id(name)
		return self._id(name, "auth_settings", "name", "id")
	end

	def _auth_settings_type_id(name)
		return self._id(name, "/auth_settings/types", "name", "id")
	end

	def _auth_settings_role_id(name)
		return self._id(name, "/auth_settings/roles", "name", "id")
	end

	def _budget_id(name)
		return self._id(name, "budgets", "name", "id")
	end

	def _project_id(name)
		return self._id(name, "projects", "name", "id")
	end

	def _product_id(name)
		return self._id(name, "catalogs/products", "name", "id")
	end

	def _credential_id(name)
		return self._id(name, "creds", "name", "id")
	end

	def _network_id(name)
		return self._id(name, "networks", "name", "id")
	end

	def _parking_calendar_id(name)
		return self._id(name, "parking_calendars", "name", "id")
	end

	def _pricing_profile_id(name)
		return self._id(name, "pricing_profile", "name", "id")
	end

	def _private_cloud_id(name, network_id)
		return self._id(name, sprintf("networks/%s/private_clouds", network_id), "name", "id")
	end

	def _rds_subnet_grouping_id(name)
		return self._id(name, "rds/subnet_groupings", "name", "id")
	end

	def _instance_id(name)
		output = nil
		content = Hash.new
		items = Array.new
		self._output = Hash.new
		self._ostrato_request(
			"get",
			"/cloud_services/set/ostrato?offset=1&limit=9999"
		)
		if (self.success)
			if (self.output["items"])
				self.output["items"].each do |item|
					if (item["name"] == name)
						output = item["id"]
						break
					end
				end
			end
		end
		self._output = Hash.new
		return output
	end

	def _parse(array, output, name_key, id_key)
		output.each do |item|
			array.push("name" => item[name_key], "id" => item[id_key])
			if (item["children"])
				self._parse(array, item["children"], name_key, id_key)
			end
		end
		return array
	end

	def _id(name, uri, name_key, id_key)
		output = nil
		content = Hash.new
		items = Array.new
		self._output = Hash.new
		self._ostrato_request(
			"get",
			sprintf("%s", uri)
		)
		if (self.success)
			items = self._parse([], self.output, name_key, id_key)
			items.each do |item|
				if (item["name"] == name)
					output = item["id"]
					break
				end
			end
		end
		self._output = Hash.new
		return output
	end

	def _uuid()
		return sprintf(
			"%s-%s-%s-%s-%s",
			SecureRandom.hex(4),
			SecureRandom.hex(2),
			SecureRandom.hex(2),
			SecureRandom.hex(2),
			SecureRandom.hex(6)
		)
	end

	def _group_ids(groups)
		group_ids = Array.new
		groups.split(/\s*,\s*/).each do |group_name|
			group_id = self._group_id(group_name)
			group_ids.push(group_id) if group_id
		end
		return group_ids
	end

	def _subnet_ids(subnets, network_name, private_cloud_name)
		subnet_names = subnets.split(/\s*,\s*/)
		subnet_ids = Array.new
		self.networks_subnets({"network_name" => network_name, "private_cloud_name" => private_cloud_name})
		if (self.success)
			self.output.each do |subnet|
				if (subnet_names.include?(subnet["name"]))
					subnet_ids.push(subnet["id"])
				end
			end
		end
		return subnet_ids
	end

	def _missing_opts_error(method, required, opts)
		return sprintf(
			"the following required \"%s\" options are missing: %s.",
			method,
			(required - opts.keys).join(", ")
		)
	end

	def _id_not_found_error(type, name)
		return sprintf(
			"could not find %s id for %s.",
			type,
			name
		)
	end

	def _failed_to_get_list_error(name)
		return sprintf(
			"failed to fetch the %s list.",
			name
		)
	end

	# Authentication
	def auth_ping(*args)
		# "method auth_ping failed: code=405; message=method not allowed"
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"auth/ping"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def validate_token(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"auth"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def change_group(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(group)
		if ((required - opts.keys).length == 0)
			group_id = self._group_id(opts["group"])
			if (group_id)
				self._ostrato_request(
					"put",
					sprintf("auth?group=%s", group_id)
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["group"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def log_out(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"delete",
				"auth"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# Authorization Settings
	def auth_settings(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"auth_settings"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def auth_settings_groups(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"auth_settings/groups"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def auth_settings_types(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"auth_settings/types"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def auth_settings_create(*args)
		# access denied
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(auth_setting_types_id domain groups name secure_auth server username)

		# parse groups and type id
		if ((required - opts.keys).length == 0)
			content["auth_setting_types_id"] = opts["auth_setting_types_id"]
			content["domain"] = opts["domain"]
			content["groups"] = opts["groups"].split(/,/)
			content["name"] = opts["name"]
			content["password"] = opts["password"] if opts["password"]
			content["secure_auth"] = opts["secure_auth"]
			content["server"] = opts["server"]
			content["username"] = opts["username"]
			
			self._ostrato_request(
				"post",
				"auth_settings",
				content
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def auth_settings_edit(*args)
		# access denied
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(auth_setting_types_id domain groups name password secure_auth server username)

		# parse groups and type id
		if ((required - opts.keys).length == 0)
			content["auth_setting_types_id"] = opts["auth_setting_types_id"]
			content["domain"] = opts["domain"]
			content["groups"] = opts["groups"].split(/,/)
			content["name"] = opts["name"]
			content["password"] = opts["password"]
			content["secure_auth"] = opts["secure_auth"]
			content["server"] = opts["server"]
			content["username"] = opts["username"]

			self._ostrato_request(
				"put",
				"auth_settings",
				content
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def auth_settings_get(*args)
		# access denied
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(auth_setting_name)
		if ((required - opts.keys).length == 0)
			#auth_setting_id = self._auth_settings_id(opts["auth_settings_name"])
			auth_setting_id = 1
			if (auth_setting_id)
				self._ostrato_request(
					"get",
					sprintf("auth_settings/%s", auth_setting_id)
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the auth settings id for \"%s\".", opts["auth_setting_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def auth_settings_imports(*args)
		# access denied
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(auth_setting_name)
		if ((required - opts.keys).length == 0)
			#auth_setting_id = self._auth_settings_id(opts["auth_settings_name"])
			auth_setting_id = 1
			if (auth_setting_id)
				self._ostrato_request(
					"get",
					sprintf("auth_settings/%s/imports", auth_setting_id)
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the auth settings id for \"%s\".", opts["auth_setting_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def auth_settings_imports_create(*args)
	end

	def auth_settings_imports_edit(*args)
	end

	def auth_settings_imports_get(*args)
	end

	def auth_settings_imports_groups(*args)
	end

	def auth_settings_roles(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"auth_settings/roles"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def auth_settings_imports_sync(*args)
	end

	# Automations
	def automations(*args)
		# type required
		# chef paramiko puppet saltstack
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			sel._ostrato_request(
				"get",
				sprintf("automations/%s", opts["type"] || "")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def automations_assignableassignable_groups(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(automation_type)
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("automations/%s/groups", opts["automation_type"])
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def automations_get(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(automation_type automation_id)
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("automations/%s/%s", opts["automation_type"], opts["automation_id"])
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def automations_create(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = Array.new
		group_ids = Array.new

		if (opts["automation_type"])
			if (opts["automation_type"] == "chef")
				required = %w(name description groups server validation_client_key user ssh_key)
				content["client_install_cmd"] = "wget -O - http://www.opscode.com/chef/install.sh | bash" unless opts["client_install_cmd"]

			elsif (opts["automation_type"] == "paramiko")
				required = %w(name description groups user ssh_key)

			elsif (opts["automation_type"] == "puppet")
				required = %w(name description groups master puppet_dir user ssh_key)

			elsif (opts["automation_type"] == "saltstack")
				required = %w(name description groups master user ssh_key)
				content["client_install_cmd"] = "wget -O - http://bootstrap.saltstack.org | sh" unless opts["client_install_cmd"]
			end

			assignable_groups = Array.new
			groups = self.automations_groups({"automation_type" => opts["automation_type"]})
			groups.each do |group|
				assignable_groups.push({
					"text" => group["group_name"],
					"value" => group["group_id"]
				})
			end

			if ((required - opts.keys).length == 0)
				opts["groups"].split(/\s*,\s*/).each do |group_name|
					group_id = self._group_id(group_name)
					group_ids.push(group_id) if group_id
				end

				if (group_ids.length > 0)
					# Common options
					content["automation_type"] = opts["automation_type"]
					content["name"] = opts["name"]
					content["description"] = opts["description"]
					content["ssh_key"] = opts["ssh_key"]
					content["user"] = opts["user"]
					content["assignable_groups"] = assignable_groups

					# Not common options
					content["crontab"] = opts["crontab"] if opts["crontab"]
					content["delete_validation_client_key"] = opts["delete_validation_client_key"] == true ? true : false
					content["environment"] = opts["environment"] if opts["environment"]
					content["first_boot"] = opts["first_boot"] if opts["first_boot"] # validate JSON
					content["is_install"] = opts["is_install"] == true ? true : false
					content["log_location"] = defined?(opts["log_location"]) ? opts["log_location"] : "STDOUT"
					content["master"] = opts["master"] if opts["master"]
					content["run_script"] = opts["run_script"] if opts["run_script"]
					content["validation_client_key"] = opts["validation_client_key"] if opts["validation_client_key"]

					content["groups"] = group_ids
						self._ostrato_request(
						"post",
						sprintf("automations/%s", opts["automation_type"]),
						content
					)
				else
					self._success = nil
					self._errors.push(sprintf("could not find a valid group id for at least one group name."))
				end
			else
				self._success = nil
				self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, "automation_type"))
		end
	end

	def automations_edit(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = Array.new
		group_ids = Array.new

		if (opts["automation_type"])
			if (opts["automation_type"] == "chef")
				required = %w(automation_id name description groups server validation_client_key user ssh_key)
				content["client_install_cmd"] = "wget -O - http://www.opscode.com/chef/install.sh | bash" unless opts["client_install_cmd"]

			elsif (opts["automation_type"] == "paramiko")
				required = %w(automation_id name description groups user ssh_key)

			elsif (opts["automation_type"] == "puppet")
				required = %w(automation_id name description groups master puppet_dir user ssh_key)

			elsif (opts["automation_type"] == "saltstack")
				required = %w(automation_id name description groups master user ssh_key)
				content["client_install_cmd"] = "wget -O - http://bootstrap.saltstack.org | sh" unless opts["client_install_cmd"]

			end

			assignable_groups = Array.new
			groups = self.automations_groups({"automation_type" => opts["automation_type"]})
			groups.each do |group|
				assignable_groups.push({
					"text" => group["group_name"],
					"value" => group["group_id"]
				})
			end

			if ((required - opts.keys).length == 0)
				opts["groups"].split(/\s*,\s*/).each do |group_name|
					group_id = self._group_id(group_name)
					group_ids.push(group_id) if group_id
				end

				if (group_ids.length > 0)
					# Common options
					content["automation_type"] = opts["automation_type"]
					content["name"] = opts["name"]
					content["description"] = opts["description"]
					content["ssh_key"] = opts["ssh_key"]
					content["user"] = opts["user"]
					content["assignable_groups"] = assignable_groups

					# Not common options
					content["crontab"] = opts["crontab"] if opts["crontab"]
					content["delete_validation_client_key"] = opts["delete_validation_client_key"] == true ? true : false
					content["environment"] = opts["environment"] if opts["environment"]
					content["first_boot"] = opts["first_boot"] if opts["first_boot"] # validate JSON
					content["is_install"] = opts["is_install"] == true ? true : false
					content["log_location"] = defined?(opts["log_location"]) ? opts["log_location"] : "STDOUT"
					content["master"] = opts["master"] if opts["master"]
					content["run_script"] = opts["run_script"] if opts["run_script"]
					content["validation_client_key"] = opts["validation_client_key"] if opts["validation_client_key"]

					content["groups"] = group_ids
						self._ostrato_request(
						"put",
						sprintf("automations/%s/%s", opts["automation_type"], opts["automation_id"]),
						content
					)
				else
					self._success = nil
					self._errors.push(sprintf("could not find a valid group id for at least one group name."))
				end
			else
				self._success = nil
				self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, "automation_type"))
		end
	end

	def automations_archive(*args)
		# "method automations_create failed: code=500; message=internal server error"
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(automation_type automation_id)
		if ((required - opts.keys).length == 0)
			content["name"] = opts["name"]
			content["description"] = opts["description"]
			# parse group IDs
			content["groups"] = opts["groups"]
			self._ostrato_request(
				"put",
				sprintf("automations/%s/%s/archive?value=true", opts["automation_type"], opts["automation_id"])
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def automations_cloudformation_validate_template(*args)
		# not yet validated
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(template_body)
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"post",
				sprintf("automations/cloudformation/validate_template"),
				# put the template json into a hash since its converted to json later
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# Budget Management
	def budgets_archive(*args)
		# not tested
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			budget_id = self._budget_id(opts["name"])
			if (budget_id)
				self._ostrato_request(
					"put",
					sprintf("budgets/%s/archive?value=true", budget_id)
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the budget id for \"%s\".", opts["name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def budgets(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"budgets"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def budgets_assignable_projects(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"budgets/projects"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def budgets_create(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(amount start_time end_time budget_name project_name)
		if ((required - opts.keys).length == 0)
			project_id = self._project_id(opts["project_name"])
			if (project_id)
				content["actions"] = []
				content["amount"] = opts["amount"]
				content["start_time"] = opts["start_time"]
				content["end_time"] = opts["end_time"]
				content["project_id"] = project_id
				content["name"] = opts["budget_name"]
				self._ostrato_request(
					"post",
					"budgets",
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the project id for \"%s\".", opts["project_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def budgets_edit(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(amount start_time end_time budget_name project_name)
		if ((required - opts.keys).length == 0)
			# split project_id and budget_id
			project_id = self._project_id(opts["project_name"])
			budget_id = self._budget_id(opts["budget_name"])
			if (project_id && budget_id)
				content["actions"] = []
				content["amount"] = opts["amount"]
				content["start_time"] = opts["start_time"]
				content["end_time"] = opts["end_time"]
				content["project_id"] = project_id
				content["name"] = opts["budget_name"]
				self._ostrato_request(
					"put",
					sprintf("budgets/%s", budget_id),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the project id for \"%s\".", opts["project_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def budgets_get(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(budget_name)
		if ((required - opts.keys).length == 0)
			budget_id = self._budget_id(opts["budget_name"])
			if (budget_id)
				self._ostrato_request(
					"get",
					sprintf("budgets/%s", budget_id),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the budget id for \"%s\".", opts["budget_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# Cloud Services Management
	def cloud_services_set(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			set_name = opts["set_name"] || "ostrato"
			offset = opts["offset"] || "1"
			limit = opts["limit"] || "9999"
			
			self._ostrato_request(
			   "get",
				sprintf("cloud_services/set/%s?offset=%s&limit=%s", set_name, offset, limit)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# Credential Management
	def creds_ssh_keys_generate(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
			   "get",
				"creds/ssh_keys/generate"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def creds_test(*args)
		# take a credential name and populate the data with the provided fields, groups, etc
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(cred provider)
		if ((required - opts.keys).length == 0)
			content["cred"] = opts["cred"]
			content["provider"] = opts["provider"]
			content["name"] = "asdf"
			content["groups"] = [1027]
			self._ostrato_request(
			   "post",
				"creds/test",
				content
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def creds_archive(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			credential_id = self._credential_id(opts["name"])
			if (credential_id)
				self._ostrato_request(
				   "put",
					sprintf("creds/%s/archive?value=true", credential_id)
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the credential id for \"%s\".", opts["name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def creds(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
			   "get",
				"creds"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def credfields(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(provider_name)
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
			   "get",
				sprintf("credfields/%s", opts["provider_name"])
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def creds_create(*args)
		# aws -	{"bucket":"","has_billing":false,"secret_access_key":"111111","account_number":"111111","access_key_id":"111111"}
		# azure - {subscription_id: "asdf", certfile: "github-ssh-public-key.pub", is_gov_cloud: false}
		# vsphere - {password: "abc123", user: "user", location: "host"}
		# openstack - {region: "asdf", telemetry: "asdf", tenantname: "asdf", user: "asdf", password: "abc123", "identity": "asdf"}
		# rackspace - {account: "asdf", apikey: "abc123", user: "asdf"}
		# softlayer - {username: "asdf", apikey: "abc123"}
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		group_ids = Array.new
		# fetch assignable groups and verify provided group are available
		# try to validate cred to some degree
		required = %w(cred groups name provider ssh_key_management ssh_key_name ssh_key_public ssh_key_private)
		if ((required - opts.keys).length == 0)
			opts["groups"].split(/\s*,\s*/).each do |group_name|
				group_id = self._group_id(group_name)
				group_ids.push(group_id) if group_id
			end

			if (group_ids.length > 0)
				content["cred"] = opts["cred"]
				content["name"] = opts["name"]
				content["provider"] = opts["provider"]
				content["groups"] = group_ids
				content["ssh_key_management"] = opts["ssh_key_management"]
				content["ssh_key_name"] = opts["ssh_key_name"]
				content["ssh_key_public"] = opts["ssh_key_public"]
				content["ssh_key_private"] = opts["ssh_key_private"]
				self._ostrato_request(
				   "post",
					"creds",
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def creds_edit(*args)
		# aws -	{"bucket":"","has_billing":false,"secret_access_key":"111111","account_number":"111111","access_key_id":"111111"}
		# azure - {subscription_id: "asdf", certfile: "github-ssh-public-key.pub", is_gov_cloud: false}
		# vsphere - {password: "abc123", user: "user", location: "host"}
		# openstack - {region: "asdf", telemetry: "asdf", tenantname: "asdf", user: "asdf", password: "abc123", "identity": "asdf"}
		# rackspace - {account: "asdf", apikey: "abc123", user: "asdf"}
		# softlayer - {username: "asdf", apikey: "abc123"}
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		group_ids = Array.new
		# fetch assignable groups and verify provided group are available
		# try to validate cred to some degree
		# allow new name for credential (new_name, old_name?)
		required = %w(cred groups name provider ssh_key_management ssh_key_name ssh_key_public ssh_key_private)
		if ((required - opts.keys).length == 0)
			opts["groups"].split(/\s*,\s*/).each do |group_name|
				group_id = self._group_id(group_name)
				group_ids.push(group_id) if group_id
			end

			if (group_ids.length > 0)
				credential_id = self._credential_id(opts["name"])
				if (credential_id)
					content["cred"] = opts["cred"]
					content["name"] = opts["name"]
					content["provider"] = opts["provider"]
					content["groups"] = group_ids
					content["ssh_key_management"] = opts["ssh_key_management"]
					content["ssh_key_name"] = opts["ssh_key_name"]
					content["ssh_key_public"] = opts["ssh_key_public"]
					content["ssh_key_private"] = opts["ssh_key_private"]
					self._ostrato_request(
					   "put",
						sprintf("creds/%s", credential_id),
						content
					)
				else
					self._success = nil
					self._errors.push(sprintf("failed to fetch the credential id for \"%s\".", opts["name"]))
				end
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def creds_get(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			credential_id = self._credential_id(opts["name"])
			if (credential_id)
				self._ostrato_request(
					"get",
					sprintf("creds/%s", credential_id)
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the credential id for \"%s\".", opts["name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def creds_available_groups(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(provider)
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("creds/groups/%s", opts["provider"])
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# Dashboard Management
	def dashboard_instances(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"dashboard/instances"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def dashboard_external_data(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"dashboard/external_data"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def dashboard_spending(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"dashboard/spending"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def dashboard_widgets_create(*args)
	end

	def dashboard_widgets_edit(*args)
	end

	def dashboard_widgets(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"dashboard/widgets"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# External Instance Data Management
	def external_data_archive(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(id)
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"put",
				sprintf("external_data/instance/%s/archive?value=true", opts["id"])
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def external_data_instance(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"external_data/instance"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def external_data_assignable_groups(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				"external_data/instance/groups"
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def external_data_instance_create(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		group_ids = Array.new
		required = %w(name url_prefix url_port url_suffix groups)
		if ((required - opts.keys).length == 0)
			opts["groups"].split(/\s*,\s*/).each do |group_name|
				group_id = self._group_id(group_name)
				group_ids.push(group_id) if group_id
			end

			if (group_ids.length > 0)
				content["name"] = opts["name"] # www.something.com
				content["url_prefix"] = opts["url_prefix"] # http|https
				content["url_port"] = opts["url_port"] # 0 - 65535
				content["url_suffix"] = opts["url_suffix"] # /ipad
				content["user_defined"] = opts["user_defined"] || {}
				content["groups"] = group_ids
				self._ostrato_request(
					"post",
					"external_data/instance",
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def external_data_instance_edit(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		group_ids = Array.new
		required = %w(id name url_prefix url_port url_suffix groups)
		if ((required - opts.keys).length == 0)
			opts["groups"].split(/\s*,\s*/).each do |group_name|
				group_id = self._group_id(group_name)
				group_ids.push(group_id) if group_id
			end

			if (group_ids.length > 0)
				content["name"] = opts["name"] # www.something.com
				content["url_prefix"] = opts["url_prefix"] # http|https
				content["url_port"] = opts["url_port"] # 0 - 65535
				content["url_suffix"] = opts["url_suffix"] # /ipad
				content["user_defined"] = opts["user_defined"] || {}
				content["groups"] = group_ids
				self._ostrato_request(
					"put",
					sprintf("external_data/instance/%s", opts["id"]),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def external_data_instance_get(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(id)
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("external_data/instance/%s", opts["id"]),
				content
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# Generic Items
	def generic_items(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("generic_items"),
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def generic_items_products(*args)
		# Need to be able to find product ID - not there yet
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(product_name)
		if ((required - opts.keys).length == 0)
			product_id = self._product_id(opts["product_name"])
			if (product_id)
				self._ostrato_request(
					"get",
					sprintf("generic_items/products/%s", product_id),
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the product id for \"%s\".", opts["product_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def generic_items_update(*args)
	end

	def generic_items_archive(*args)
	end

	# Get Item Pricing
	def marketplace_pricing(*args)
		# Need more info here
	end

	# Group Management
	def groups_archive(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				# Make configurable
				sprintf("groups?hierarchy=1"),
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def groups(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				# Make configurable
				sprintf("groups?hierarchy=1"),
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def groups_assignable_groups(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("groups/parents")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def groups_assignable_parent_group(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(group_name)
		if ((required - opts.keys).length == 0)
			group_id = self._group_id(opts["group_name"])
			if (group_id)
				self._ostrato_request(
					"get",
					sprintf("groups/%s/parents", group_id)
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["group_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def groups_create(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(group_name parent_group_name)
		if ((required - opts.keys).length == 0)
			group_id = self._group_id(opts["parent_group_name"])
			if (group_id)
				content["name"] = opts["group_name"]
				content["parent_groups_id"] = group_id
				content["approval_required"] = opts["approval_required"] == 1 ? 1 : 0
				self._ostrato_request(
					"post",
					sprintf("groups"),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["parent_group_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def groups_edit(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(group_name parent_group_name)
		if ((required - opts.keys).length == 0)
			group_id = self._group_id(opts["group_name"])
			parent_group_id = self._group_id(opts["parent_group_name"])
			# You will want to combine error messages so that one message can trap both conditions
			unless (group_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["group_name"]))
				return
			end

			unless (parent_group_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["parent_group_name"]))
				return
			end

			content["name"] = opts["new_group_name"] if opts["new_group_name"]
			content["parent_groups_id"] = parent_group_id
			content["approval_required"] = opts["approval_required"] == 1 ? 1 : 0
			self._ostrato_request(
				"put",
				sprintf("groups/%s", group_id),
				content
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def groups_get(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(group_name)
		if ((required - opts.keys).length == 0)
			group_id = self._group_id(opts["group_name"])
			unless (group_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["group_name"]))
				return
			end

			self._ostrato_request(
				"get",
				sprintf("groups/%s", group_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# Manage Compute Items v22.x

	# Manage Ingestions
	def ingestions(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("ingestions")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def ingest(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"post",
				sprintf("ingestions")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def ingestions_groups(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("ingestions/groups")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def ingest_group_cred(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(cred_name group_name)
		if ((required - opts.keys).length == 0)
			group_id = self._group_id(opts["group_name"])
			cred_id = self._credential_id(opts["cred_name"])
			# You will want to combine error messages so that one message can trap both conditions
			unless (group_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["group_name"]))
				return
			end

			unless (cred_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the credential id for \"%s\".", opts["cred_name"]))
				return
			end
			
			self._ostrato_request(
				"post",
				sprintf("ingestions/creds/%s/groups/%s", cred_id, group_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def ingestions_creds_latest(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(cred_name)
		if ((required - opts.keys).length == 0)
			cred_id = self._credential_id(opts["cred_name"])
			# You will want to combine error messages so that one message can trap both conditions
			unless (cred_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the credential id for \"%s\".", opts["cred_name"]))
				return
			end

			self._ostrato_request(
				"get",
				sprintf("ingestions/creds/%s/latest", cred_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# Marketplace (Catalog)
	def catalogs_products(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("catalogs/products?_admin=1")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def catalogs_products_assignable_groups(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("catalogs/products/groups")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# get external supplied product option choices???? need to wait on this one

	def catalogs_products_archive(*args)
		# Nope. Need to be able to create a product. WHERE???
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(product_name)
		if ((required - opts.keys).length == 0)
			product_id = self._product_id(opts["product_name"])
			unless (product_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the product id for \"%s\".", opts["product_name"]))
				return
			end
			self._ostrato_request(
				"put",
				sprintf("catalogs/products/%s/archive?value=true", product_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def catalogs_products(*args)
		# Works
		# <filter_label>: any other word will indicate a product option filter_label that is used to reduce the set of products.
		# huh??
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		qs = Array.new
		if ((required - opts.keys).length == 0)
			qs.push(sprintf("_admin=%s", opts["_admin"])) if opts["_admin"]
			qs.push(sprintf("_provider=%s", opts["_provider"])) if opts["_provider"]
			qs.push(sprintf("_cloud_service_type=%s", opts["_cloud_service_type"])) if opts["_cloud_service_type"]
			qs.push(sprintf("_orderable=%s", opts["_orderable"])) if opts["_orderable"]
			qs.push(sprintf("_range=%s", opts["_range"])) if opts["_range"]
			qs.push(sprintf("_search=%s", opts["_search"])) if opts["_search"]
			self._ostrato_request(
				"get",
				sprintf("catalogs/products?%s", qs.join("&"))
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def catalogs_products_create(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(base_price description price_time_unit title options groups)
		group_ids = Array.new

		if ((required - opts.keys).length == 0)
			opts["groups"].split(/\s*,\s*/).each do |group_name|
				group_id = self._group_id(group_name)
				group_ids.push(group_id) if group_id
			end

			if (group_ids.length > 0)
				content["base_price"] = opts["base_price"]
				content["description"] = opts["description"]
				content["price_time_unit"] = opts["price_time_unit"]
				content["title"] = opts["title"]
				content["options"] = opts["options"]

				content["cloud_service_type"] = "generic"
				content["groups"] = group_ids
				self._ostrato_request(
					"post",
					sprintf("catalogs/products"),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def catalogs_products_get(*args)
	end

	def carts_products_get(*args)
	end

	# Metrics
	def metrics_offenders(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(metric_name operator threshold interval)
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf(
					"metrics/offenders/%s?operator=%s&threshold=%s&interval=%s",
					opts["metric_name"],
					opts["operator"],
					opts["threshold"],
					opts["interval"]
				)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def cloud_services_metrics(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(instance_name interval)
		if ((required - opts.keys).length == 0)
			instance_id = self._instance_id(opts["instance_name"])
			unless (instance_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the instance id for \"%s\".", opts["instance_name"]))
				return
			end
			self._ostrato_request(
				"get",
				sprintf("cloud_services/%s/metrics?interval=%s", instance_id, opts["interval"])
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def metrics_list_intervals(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("metrics/list/intervals")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def metrics_list_metrics(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("metrics/list/metrics")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	# Network Management
	def networks(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("networks")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_assignable_groups(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("networks/groups")
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_network_create(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(description groups name)
		group_ids = Array.new
		if ((required - opts.keys).length == 0)
			opts["groups"].split(/\s*,\s*/).each do |group_name|
				group_id = self._group_id(group_name)
				group_ids.push(group_id) if group_id
			end

			if (group_ids.length > 0)
				content["description"] = opts["description"]
				content["name"] = opts["name"]
				content["groups"] = group_ids
				self._ostrato_request(
					"post",
					sprintf("networks"),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_network_edit(*args)
	end

	def networks_network_get(*args)
	end
	
	def networks_archive(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name)
		if ((required - opts.keys).length == 0)
			network_id = self._network_id(opts["network_name"])
			unless (network_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the network id for \"%s\".", opts["network_name"]))
				return
			end
			self._ostrato_request(
				"put",
				sprintf("networks/%s/archive?value=true", network_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_deploy(*args)
		# DO NOT TEST ON A LIVE ACCOUNT
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name)
		if ((required - opts.keys).length == 0)
			network_id = self._network_id(opts["network_name"])
			unless (network_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the network id for \"%s\".", opts["network_name"]))
				return
			end
			self._ostrato_request(
				"put",
				sprintf("networks/%s/deploy", network_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_available_locations_pg(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(provider_name group_name)
		if ((required - opts.keys).length == 0)
			# How the heck do I get provider ID?
			provider_id = self.providers[opts["provider_name"]]
			group_id = self._group_id(opts["group_name"])
			unless (provider_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the provider id for \"%s\".", opts["provider_name"]))
				return
			end
			unless (group_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["group_name"]))
				return
			end
			self._ostrato_request(
				"get",
				sprintf("providers/%s/groups/%s/locations", provider_id, group_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	## Locations
	def networks_locations_create(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name group_name provider_name location_name)
		if ((required - opts.keys).length == 0)
			network_id = self._network_id(opts["network_name"])
			group_id = self._group_id(opts["group_name"])
			unless (network_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the network id for \"%s\".", opts["network_name"]))
				return
			end
			unless (group_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["group_name"]))
				return
			end

			self.networks_available_locations_pg({
				"provider_name" => opts["provider_name"],
				"group_name" => opts["group_name"]
			})

			if (self.success)
				valid_locations = Array.new
				self.output.each do |location|
					valid_locations.push(location["name"])
				end

				if (valid_locations.include?(opts["location_name"]))
					self._output = Hash.new

					content["location_name"] = opts["location_name"]
					content["name"] = opts["location_name"]
					content["id"] = self._uuid
					content["group_id"] = group_id
					content["group_name"] = opts["group_name"]
					content["groups_list"] = []
					content["provider_name"] = opts["provider_name"]
					content["provider_id"] = self.providers[opts["provider_name"]]
					self._ostrato_request(
						"post",
						sprintf("networks/%s/locations", network_id),
						content
					)
				else
					self._success = nil
					self._errors.push(sprintf(
						"invalid location for provider %s. valid locations are: %s.",
						opts["provider_name"],
						valid_locations.sort.join(", ")
					))
				end
			end
		end
	end

	def networks_locations_delete(*args)
		# "method networks_locations_delete failed: code=405; message=method not allowed"
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name group_name provider_name location_name)
		if ((required - opts.keys).length == 0)
			network_id = self._network_id(opts["network_name"])
			group_id = self._group_id(opts["group_name"])
			unless (network_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the network id for \"%s\".", opts["network_name"]))
				return
			end
			unless (group_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the group id for \"%s\".", opts["group_name"]))
				return
			end

			self.networks_available_locations_pg({
				"provider_name" => opts["provider_name"],
				"group_name" => opts["group_name"]
			})

			if (self.success)
				valid_locations = Array.new
				self.output.each do |location|
					valid_locations.push(location["name"])
				end

				if (valid_locations.include?(opts["location_name"]))
					self._output = Hash.new

					content["location_name"] = opts["location_name"]
					content["name"] = opts["location_name"]
					content["id"] = self._uuid
					content["group_id"] = group_id
					content["group_name"] = opts["group_name"]
					content["groups_list"] = []
					content["provider_name"] = opts["provider_name"]
					content["provider_id"] = self.providers[opts["provider_name"]]
					self._ostrato_request(
						"delete",
						sprintf("networks/%s/locations", network_id),
						content
					)
				else
					self._success = nil
					self._errors.push(sprintf(
						"invalid location for provider %s. valid locations are: %s.",
						opts["provider_name"],
						valid_locations.sort.join(", ")
					))
				end
			end
		end
	end

	def networks_locations(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name)
		if ((required - opts.keys).length == 0)
			network_id = self._network_id(opts["network_name"])
			unless (network_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the network id for \"%s\".", opts["network_name"]))
				return
			end
			self._ostrato_request(
				"get",
				sprintf("networks/%s/locations", network_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	## Private clouds
	def networks_private_clouds(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name)
		if ((required - opts.keys).length == 0)
			network_id = self._network_id(opts["network_name"])
			unless (network_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the network id for \"%s\".", opts["network_name"]))
				return
			end
			self._ostrato_request(
				"get",
				sprintf("networks/%s/private_clouds", network_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_private_clouds_create(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name cidr_block name)
		if ((required - opts.keys).length == 0)
			network_id = self._network_id(opts["network_name"])
			unless (network_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the network id for \"%s\".", opts["network_name"]))
				return
			end

			content["cidr_block"] = opts["cidr_block"]
			content["name"] = opts["name"]
			self._ostrato_request(
				"post",
				sprintf("networks/%s/private_clouds", network_id),
				content
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_private_clouds_edit(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name private_cloud_name)
		if ((required - opts.keys).length == 0)
			network_id, private_cloud_id = nil, nil
			self.networks_private_clouds({"network_name" => opts["network_name"]})
			if (self.success)
				self.output.each do |private_cloud|
					if (private_cloud["name"] == opts["private_cloud_name"])
						network_id = private_cloud["network_id"]
						private_cloud_id = private_cloud["id"]
						self._output = Hash.new
						break
					end
				end

				if (network_id && private_cloud_id)
					content["name"] = opts["new_name"] if opts["new_name"]
					self._ostrato_request(
						"put",
						sprintf("networks/%s/private_clouds/%s", network_id, private_cloud_id),
						content
					)
				else
					self._success = nil
					self._errors.push(sprintf("failed to get network id and/or private cloud id."))
				end
			else
				self._success = nil
				self._errors.push(sprintf("failed to get a list of private clouds for %s.", opts["network_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_private_clouds_get(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name private_cloud_name)
		if ((required - opts.keys).length == 0)
			network_id, private_cloud_id = nil, nil
			self.networks_private_clouds({"network_name" => opts["network_name"]})
			if (self.success)
				self.output.each do |private_cloud|
					if (private_cloud["name"] == opts["private_cloud_name"])
						self._success = 1
						self._output = private_cloud
						break
					end
				end
			else
				self._success = nil
				self._errors.push(sprintf("failed to get a list of private clouds for %s.", opts["network_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_private_clouds_archive(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name private_cloud_name)
		if ((required - opts.keys).length == 0)
			network_id, private_cloud_id = nil, nil
			self.networks_private_clouds({"network_name" => opts["network_name"]})
			if (self.success)
				self.output.each do |private_cloud|
					if (private_cloud["name"] == opts["private_cloud_name"])
						network_id = private_cloud["network_id"]
						private_cloud_id = private_cloud["id"]
						self._output = Hash.new
						break
					end
				end

				if (network_id && private_cloud_id)
					self._ostrato_request(
						"put",
						sprintf("networks/%s/private_clouds/%s/archive?value=true", network_id, private_cloud_id)
					)
				else
					self._success = nil
					self._errors.push(sprintf("failed to get network id and/or private cloud id."))
				end
			else
				self._success = nil
				self._errors.push(sprintf("failed to get a list of private clouds for %s.", opts["network_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	## Subnets
	def networks_subnets(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name private_cloud_name)
		if ((required - opts.keys).length == 0)
			network_id, private_cloud_id = nil, nil
			self.networks_private_clouds({"network_name" => opts["network_name"]})
			if (self.success)
				self.output.each do |private_cloud|
					if (private_cloud["name"] == opts["private_cloud_name"])
						network_id = private_cloud["network_id"]
						private_cloud_id = private_cloud["id"]
						self._output = Hash.new
						break
					end
				end

				if (network_id && private_cloud_id)
					self._ostrato_request(
						"get",
						sprintf("networks/%s/private_clouds/%s/subnets", network_id, private_cloud_id)
					)
				else
					self._success = nil
					self._errors.push(sprintf("failed to get network id and/or private cloud id."))
				end
			else
				self._success = nil
				self._errors.push(sprintf("failed to get a list of private clouds for %s.", opts["network_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_subnets_create(*args)
		# 403
		# Need to understand the dependencies for subnets
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name private_cloud_name cidr_block name deployed_locations)
		if ((required - opts.keys).length == 0)
			network_id, private_cloud_id = nil, nil
			self.networks_private_clouds({"network_name" => opts["network_name"]})
			if (self.success)
				self.output.each do |private_cloud|
					if (private_cloud["name"] == opts["private_cloud_name"])
						network_id = private_cloud["network_id"]
						private_cloud_id = private_cloud["id"]
						self._output = Hash.new
						break
					end
				end

				if (network_id && private_cloud_id)
					content["cidr_block"] = opts["cidr_block"]
					content["name"] = opts["name"]
					content["deployed_locations"] = opts["deployed_locations"]
					self._ostrato_request(
						"post",
						sprintf("networks/%s/private_clouds/%s/subnets", network_id, private_cloud_id),
						content
					)
				else
					self._success = nil
					self._errors.push(sprintf("failed to get network id and/or private cloud id."))
				end
			else
				self._success = nil
				self._errors.push(sprintf("failed to get a list of private clouds for %s.", opts["network_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	## Firewalls
	def networks_firewalls(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name)
		if ((required - opts.keys).length == 0)
			network_id = self._network_id(opts["network_name"])
			unless (network_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the network id for \"%s\".", opts["network_name"]))
				return
			end
			self._ostrato_request(
				"get",
				sprintf("networks/%s/firewalls", network_id)
			)
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_firewalls_create(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name name description groups inbound outbound)
		group_ids = Array.new
		if ((required - opts.keys).length == 0)
			network_id = self._network_id(opts["network_name"])
			unless (network_id)
				self._success = nil
				self._errors.push(sprintf("failed to fetch the network id for \"%s\".", opts["network_name"]))
				return
			end

			opts["groups"].split(/\s*,\s*/).each do |group_name|
				group_id = self._group_id(group_name)
				group_ids.push(group_id) if group_id
			end

			if (group_ids.length > 0)
				content["ports"] = {}
				content["name"] = opts["name"]
				content["description"] = opts["description"]
				content["ports"]["inbound"] = opts["inbound"]
				content["ports"]["outbound"] = opts["outbound"]
				content["groups"] = group_ids
				self._ostrato_request(
					"post",
					sprintf("networks/%s/firewalls", network_id),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_firewalls_edit(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name firewall_name description groups inbound outbound)
		group_ids = Array.new
		if ((required - opts.keys).length == 0)
			self.networks_firewalls("network_name" => opts["network_name"])
			if (self.success)
				firewall_obj = nil
				self.output.each do |firewall|
					if (firewall["name"] == opts["firewall_name"])
						firewall_obj = firewall.clone
						break
					end
				end
				if (firewall_obj)
					opts["groups"].split(/\s*,\s*/).each do |group_name|
						group_id = self._group_id(group_name)
						group_ids.push(group_id) if group_id
					end

					if (group_ids.length > 0)
						content["ports"] = {}
						content["name"] = opts["new_name"] if opts["new_name"]
						content["description"] = opts["description"]
						content["ports"]["inbound"] = opts["inbound"]
						content["ports"]["outbound"] = opts["outbound"]
						content["groups"] = group_ids
						self._ostrato_request(
				  			"put",
							sprintf("networks/%s/firewalls/%s", firewall_obj["network_id"], firewall_obj["id"]),
							content
						)
					else
						self._success = nil
						self._errors.push(sprintf("could not find a valid group id for at least one group name."))
					end
				else
					self._success = nil
					self._errors.push(sprintf("failed to get firewall information for %s.", opts["firewall_name"]))
				end
			else
				self._success = nil
				self.errors.push(sprintf("failed to get a list of firewalls for %s.", opts["network_name"]))
			end
		else
			self._success = nil
			self._errors.push(sprintf("the following required \"%s\" options are missing: %s.", __method__, (required - opts.keys).join(", ")))
		end
	end

	def networks_firewalls_get(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name firewall_name)
		if ((required - opts.keys).length == 0)
			self.networks_firewalls("network_name" => opts["network_name"])
			if (self.success)
				self.output.each do |firewall|
					if (firewall["name"] == opts["firewall_name"])
						self._success = 1
						self._output = firewall.clone
						break
					end
				end
			else
				self._success = nil
				self._errors.push(sprintf("failed to get a list of firewalls for %s.", opts["network_name"]))
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def networks_firewalls_archive(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(network_name firewall_name)
		if ((required - opts.keys).length == 0)
			network_id, firewall_id = nil, nil
			self.networks_firewalls("network_name" => opts["network_name"])
			if (self.success)
				self.output.each do |firewall|
					if (firewall["name"] == opts["firewall_name"])
						network_id = firewall["network_id"]
						firewall_id = firewall["id"]
						break
					end
				end
				if (network_id && firewall_id)
					self._ostrato_request(
						"put",
						sprintf("networks/%s/firewalls/%s/archive?value=true", network_id, firewall_id)
					)
				else
					self._success = nil
					self._errors.push(sprintf("failed to get network id and/or firewall id."))
				end
			else
				self._success = nil
				self.errors.push(sprintf("failed to get a list of firewalls for %s.", opts["network_name"]))
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	# Order Management
	def orders(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		qs = Array.new
		if ((required - opts.keys).length == 0)
			qs.push(sprintf("_approve=%s", opts["_approve"])) if opts["_approve"]
			qs.push(sprintf("_group_name=%s", opts["_group_name"])) if opts["_group_name"]
			qs.push(sprintf("_range_date_from=%s", opts["_range_date_from"])) if opts["_range_date_from"]
			qs.push(sprintf("_range_date_to=%s", opts["_range_date_to"])) if opts["_range_date_to"]
			qs.push(sprintf("_range_total_from=%s", opts["_range_total_from"])) if opts["_range_total_from"]
			qs.push(sprintf("_range_total_to=%s", opts["_range_total_to"])) if opts["_range_total_to"]
			qs.push(sprintf("_status=%s", opts["_status"])) if opts["_status"]
			qs.push(sprintf("_username=%s", opts["_username"])) if opts["_username"]
			self._ostrato_request(
				"get",
				sprintf("orders?%s", qs.join("&"))
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def orders_get(*args)
	end

	def orders_approve(*args)
	end

	def orders_reject(*args)
	end

	# Order Products
	# hmm I don't know what to do here

	# Parking Calendar Management
	def parking_calendars_savings_group(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(group_name)
		if ((required - opts.keys).length == 0)
			group_id = self._group_id(opts["group_name"])
			unless (group_id)
				self._success = nil
				self._errors.push( self._id_not_found_error("group", opts["group_name"]) )
				return
			end
			self._ostrato_request(
				"get",
				sprintf("parking_calendars/savings/groups/%s", group_id)
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def parking_calendars_savings_cloud_services(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(instance_name)
		if ((required - opts.keys).length == 0)
			instance_id = self._instance_id(opts["instance_name"])
			unless (instance_id)
				self._success = nil
				self._errors.push( self._id_not_found_error("instance", opts["instance_name"]) )
				return
			end
			self._ostrato_request(
				"get",
				sprintf("parking_calendars/savings/cloud_services/%s", instance_id)
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def parking_calendars_archive(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			parking_calendar_id = self._parking_calendar_id(opts["name"])
			unless (parking_calendar_id)
				self._success = nil
				self._errors.push( self._id_not_found_error("parking calendar", opts["name"]) )
				return
			end

			self._ostrato_request(
				"put",
				sprintf("parking_calendars/%s/archive?value=true", parking_calendar_id)
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def parking_calendars(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("parking_calendars")
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def parking_calendars_assignable_groups(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("parking_calendars/groups")
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def parking_calendars_get(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(parking_calendar_name)
		if ((required - opts.keys).length == 0)
			parking_calendar_id = self._parking_calendar_id(opts["parking_calendar_name"])
			unless (parking_calendar_id)
				self._success = nil
				self._errors.push( self._id_not_found_error("parking calendar", opts["parking_calendar_name"]) )
				return
			end
			self._ostrato_request(
				"get",
				sprintf("parking_calendars/%s", parking_calendar_id)
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end	
	end

	def parking_calendars_create(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name times groups)
		if ((required - opts.keys).length == 0)
			group_ids = self._group_ids(opts["groups"])
			if (group_ids.length > 0)
				content["name"] = opts["name"]
				content["times"] = opts["times"]
				content["groups"] = group_ids
				self._ostrato_request(
					"post",
					sprintf("parking_calendars"),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def parking_calendars_edit(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name times groups)
		if ((required - opts.keys).length == 0)
			group_ids = self._group_ids(opts["groups"])
			if (group_ids.length > 0)
				parking_calendar_id = self._parking_calendar_id(opts["name"])
				unless (parking_calendar_id)
					self._success = nil
					self._errors.push( self._id_not_found_error("parking calendar", opts["name"]) )
					return
				end

				content["name"] = opts["new_name"] if opts["new_name"]
				content["times"] = opts["times"]
				content["groups"] = group_ids
				self._ostrato_request(
					"put",
					sprintf("parking_calendars/%s", parking_calendar_id),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	# Permissions
	def permissions(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("permissions")
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def auth(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(user pass)
		if ((required - opts.keys).length == 0)
			content["user"] = opts["user"]
			content["pass"] = opts["pass"]
			self._ostrato_request(
				"post",
				sprintf("auth"),
				content
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	# Pricing Profiles Management
	def pricing_profiles_archive(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			pricing_profile_id = self._pricing_profile_id(opts["name"])
			unless (pricing_profile_id)
				self._success = nil
				self._errors.push( self._id_not_found_error("pricing profile", opts["name"]) )
				return
			end
			self._ostrato_request(
				"put",
				sprintf("pricing_profile/%s/archive?value=true", pricing_profile_id)
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def pricing_profiles(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("pricing_profile")
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def pricing_profiles_assignable_groups(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("pricing_profile/groups")
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def pricing_profiles_create(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name description groups)
		if ((required - opts.keys).length == 0)
			group_ids = self._group_ids(opts["groups"])
			if (group_ids.length > 0)
				content["name"] = opts["name"]
				content["description"] = opts["description"]
				content["groups"] = group_ids
				content["use_ingested_pricing"] = defined?(opts["use_ingested_pricing"]) ? opts["use_ingested_pricing"] : true
				self._ostrato_request(
					"post",
					sprintf("pricing_profile"),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def pricing_profiles_edit(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name description groups)
		if ((required - opts.keys).length == 0)
			group_ids = self._group_ids(opts["groups"])
			if (group_ids.length > 0)
				pricing_profile_id = self._pricing_profile_id(opts["name"])
				unless (pricing_profile_id)
					self._success = nil
					self._errors.push( self._id_not_found_error("pricing profile", opts["name"]) )
					return
				end
				content["name"] = opts["new_name"] if opts["new_name"]
				content["description"] = opts["description"]
				content["groups"] = group_ids
				content["use_ingested_pricing"] = defined?(opts["use_ingested_pricing"]) ? opts["use_ingested_pricing"] : true
				self._ostrato_request(
					"put",
					sprintf("pricing_profile/%s", pricing_profile_id),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def pricing_profiles_get(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			pricing_profile_id = self._pricing_profile_id(opts["name"])
			if (pricing_profile_id)
				self._ostrato_request(
					"get",
					sprintf("pricing_profile/%s", pricing_profile_id)
				)
			else
				self._success = nil
				self._errors.push( self._id_not_found_error("pricing profile", opts["name"]) )
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	# Projects Management
	def projects_archive(*args)
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			project_id = self._project_id(opts["name"])
			unless (project_id)
				self._success = nil
				self._errors.push( self._id_not_found_error("project", opts["name"]) )
				return
			end
			self._ostrato_request(
				"put",
				sprintf("projects/%s/archive?value=true", project_id)
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def projects(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("projects")
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def projects_get(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			project_id = self._project_id(opts["name"])
			if (project_id)
				self._ostrato_request(
					"get",
					sprintf("projects/%s", project_id)
				)
			else
				self._success = nil
				self._errors.push( self._id_not_found_error("project", opts["name"]) )
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def projects_assignable_groups(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("projects/groups")
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def projects_create(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name groups)
		if ((required - opts.keys).length == 0)
			group_ids = self._group_ids(opts["groups"])
			if (group_ids.length > 0)
				content["name"] = opts["name"]
				content["groups"] = group_ids
				self._ostrato_request(
					"post",
					sprintf("projects"),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def projects_edit(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name groups)
		if ((required - opts.keys).length == 0)
			group_ids = self._group_ids(opts["groups"])
			if (group_ids.length > 0)
				project_id = self._project_id(opts["name"])
				unless (project_id)
					self._success = nil
					self._errors.push( self._id_not_found_error("project", opts["name"]) )
					return
				end
				content["name"] = opts["new_name"] if opts["new_name"]
				content["groups"] = group_ids
				self._ostrato_request(
					"put",
					sprintf("projects/%s", project_id),
					content
				)
			else
				self._success = nil
				self._errors.push(sprintf("could not find a valid group id for at least one group name."))
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	# RDS Subnet Groupings
	def rds_subnet_groupings(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w()
		if ((required - opts.keys).length == 0)
			self._ostrato_request(
				"get",
				sprintf("rds/subnet_groupings")
			)
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def rds_subnet_groupings_create(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name description groups network_name private_cloud_name subnets)
		if ((required - opts.keys).length == 0)
			private_cloud_id = nil
			network_id = self._network_id(opts["network_name"])
			if (network_id)
				private_cloud_id = self._private_cloud_id(opts["private_cloud_name"], network_id)
				if (private_cloud_id)
					subnet_ids = self._subnet_ids(opts["subnets"], opts["network_name"], opts["private_cloud_name"])
					if (subnet_ids.length > 0)
						group_ids = self._group_ids(opts["groups"])
						if (group_ids.length > 0)
							content["description"] = opts["description"]
							content["groups"] = group_ids
							content["name"] = opts["name"]
							content["network_id"] = network_id
							content["network_private_cloud_id"] = private_cloud_id
							content["subnet_ids"] = subnet_ids
							self._ostrato_request(
								"post",
								sprintf("rds/subnet_groupings"),
								content
							)
						else
							self._success = nil
							self._errors.push(sprintf("could not find a valid group id for at least one group name."))
						end
					else
						self._success = nil
						self._errors.push(sprintf("could not find a valid subnet id for at least one subnet name."))
					end
				else
					self._errors.push( self._id_not_found_error("private cloud", opts["private_cloud_name"]) )
				end
			else
				self._errors.push( self._id_not_found_error("network", opts["network_name"]) )
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def rds_subnet_groupings_edit(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name description groups network_name private_cloud_name subnets)
		if ((required - opts.keys).length == 0)
			rds_subnet_grouping_id = self._rds_subnet_grouping_id(opts["name"])
			if (rds_subnet_grouping_id)
				network_id = self._network_id(opts["network_name"])
				if (network_id)
					private_cloud_id = self._private_cloud_id(opts["private_cloud_name"], network_id)
					if (private_cloud_id)
						subnet_ids = self._subnet_ids(opts["subnets"], opts["network_name"], opts["private_cloud_name"])
						if (subnet_ids.length > 0)
							group_ids = self._group_ids(opts["groups"])
							if (group_ids.length > 0)
								content["description"] = opts["description"]
								content["groups"] = group_ids
								content["network_id"] = network_id
								content["network_private_cloud_id"] = private_cloud_id
								content["subnet_ids"] = subnet_ids
								self._ostrato_request(
									"put",
									sprintf("rds/subnet_groupings/%s", rds_subnet_grouping_id),
									content
								)
							else
								self._success = nil
								self._errors.push(sprintf("could not find a valid group id for at least one group name."))
							end
						else
							self._success = nil
							self._errors.push(sprintf("could not find a valid subnet id for at least one subnet name."))
						end
					else
						self._success = nil
						self._errors.push( self._id_not_found_error("private cloud", opts["private_cloud_name"]) )
					end
				else
					self._success = nil
					self._errors.push( self._id_not_found_error("network", opts["network_name"]) )
				end
			else
				self._success = nil
				self._errors.push( self._id_not_found_error("rds subnet grouping", opts["name"]) )
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def rds_subnet_groupings_get(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			rds_subnet_grouping_id = self._rds_subnet_grouping_id(opts["name"])
			if (rds_subnet_grouping_id)
				self._ostrato_request(
					"get",
					sprintf("rds/subnet_groupings/%s", rds_subnet_grouping_id)
				)
			else
				self._success = nil
				self._errors.push( self._id_not_found_error("rds subnet grouping", opts["name"]) )
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def rds_subnet_groupings_archive(*args)
		# Works
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			rds_subnet_grouping_id = self._rds_subnet_grouping_id(opts["name"])
			if (rds_subnet_grouping_id)
				self._ostrato_request(
					"put",
					sprintf("rds/subnet_groupings/%s/archive?value=true", rds_subnet_grouping_id)
				)
			else
				self._success = nil
				self._errors.push( self._id_not_found_error("rds subnet grouping", opts["name"]) )
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def rds_subnet_groupings_deploy(*args)
		# Untested - do not want to deploy
		opts = args[0] || Hash.new
		content = Hash.new
		self._output = Hash.new
		required = %w(name)
		if ((required - opts.keys).length == 0)
			rds_subnet_grouping_id = self._rds_subnet_grouping_id(opts["name"])
			if (rds_subnet_grouping_id)
				self._ostrato_request(
					"put",
					sprintf("rds/subnet_groupings/%s/deploy", rds_subnet_grouping_id)
				)
			else
				self._success = nil
				self._errors.push( self._id_not_found_error("rds subnet grouping", opts["name"]) )
			end
		else
			self._success = nil
			self._errors.push(self._missing_opts_error(__method__, required, opts))
		end
	end

	def _ostrato_request(*args)
		http_method = args[0]
		uri = args[1]
		content = args[2] || nil

		req = nil
		method = caller[0][/`.*'/][1..-2]
		self._debug_text(sprintf("executing method: %s", method))
		errors, message = Array.new, Array.new

		url = sprintf(
			"%s/%s",
			self.base_url,
			uri
		)
		enc = URI.escape(url)
		uri = URI(enc)
		http = Net::HTTP.new(uri.host, uri.port)
		http.use_ssl = true
		http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		http.read_timeout = 10
		payload = content.to_json if content

		if (http_method =~ /^get$/i)
			req = Net::HTTP::Get.new(uri.request_uri)

		elsif (http_method =~ /^post$/i)
			req = Net::HTTP::Post.new(uri.request_uri)
			req.body = payload if payload

		elsif (http_method =~ /^put$/i)
			req = Net::HTTP::Put.new(uri.request_uri)
			req.body = payload if payload

		elsif (http_method =~ /^delete$/i)
			req = Net::HTTP::Delete.new(uri.request_uri)			
			req.body = payload if payload
		end

		req["Content-Type"] = "application/json"
		req["X-Auth-Token"] = self._token if self._token

		self._debug_text("fetching #{url}")
		self._debug_text("payload: #{payload}") if payload
		res = http.request(req)

		if (res.code =~ /^2\d\d$/)
			hashref = self._validate_json(res.body)
			if (hashref)
				self._success = 1
				self._output = hashref.clone
			else
				self._success = 1
				self._output = {}
			end
		else
			hashref = self._validate_json(res.body)
			if (hashref)
				self._success = nil
				if (hashref["message"])
					# There may be other data... check that out
					self._errors.push(hashref["message"].downcase)
				else
					self._errors.push("an unknown error has occurred.")
				end
			else
				message.push(sprintf("code=%s", res.code))
				message.push(sprintf("message=%s", res.message.downcase))
				message.push(sprintf(res.body.downcase)) if res.body
				self._success = nil
				self._errors.push(sprintf("method %s failed: %s", method, message.join("; ")))
			end
		end
	end
end
