<?php

namespace PHPTerminalModulesFirewall;

use Carbon\Carbon;
use PHPFirewall\Firewall as PHPFirewallFirewall;
use PHPTerminal\Modules;
use PHPTerminal\Terminal;

class Firewall extends Modules
{
    protected $terminal;

    protected $command;

    protected $firewallPackage;

    protected $firewallConfig;

    protected $auth;

    public function init(Terminal $terminal = null, $command) : object
    {
        $this->terminal = $terminal;

        $this->command = $command;

        $this->firewallPackage = new PHPFirewallFirewall;

        $this->getFirewallConfig();

        return $this;
    }

    protected function getFirewallConfig()
    {
        $firewall = $this->firewallPackage->getFirewallConfig();

        if (isset($firewall['response']['responseCode']) && $firewall['response']['responseCode'] == 0) {
            $this->firewallConfig = $firewall['response']['responseData'];
        }

        if (!$this->firewallConfig) {
            $this->terminal->addResponse('Error retrieving firewall details. Contact developer!', 1);

            return false;
        }
    }

    public function getCommands() : array
    {
        $commands =
            [
                [
                    "availableAt"   => "enable",
                    "command"       => "",
                    "description"   => "show commands",
                    "function"      => ""
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "fw show run",
                    "description"   => "Show firewall module running configuration",
                    "function"      => "fw"
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "fw show filters",
                    "description"   => "Show firewall filters",
                    "function"      => "fw"
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "fw show filter",
                    "description"   => "show filter {id}",
                    "function"      => "fw"
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "fw search filter",
                    "description"   => "fw search filter {address}. Ex: fw search filter 10.0.0. This command performs a like search, so anything with 10.0.0 will be searched in addresses.",
                    "function"      => "fw"
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "",
                    "description"   => "",
                    "function"      => ""
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "",
                    "description"   => "IP Commands",
                    "function"      => ""
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "fw check ip",
                    "description"   => "fw check ip {address}. Check state of an ip address, if it is being blocked/allowed/monitored by the firewall.",
                    "function"      => "fw"
                ],
            ];

        if ($this->firewallConfig && isset($this->firewallConfig['ip2location_io_api_key']) && $this->firewallConfig['ip2location_io_api_key'] !== '') {
            //grab ip details from ip2location.io api
            array_push($commands,
                [
                    "availableAt"   => "enable",
                    "command"       => "fw show ip details",
                    "description"   => "fw show ip details {address}. Get ip details from ip2location io API.",
                    "function"      => "fw"
                ],
            );
        }

        //Geo Commands
        array_push($commands,
            [
                "availableAt"   => "enable",
                "command"       => "",
                "description"   => "",
                "function"      => ""
            ],
            [
                "availableAt"   => "enable",
                "command"       => "",
                "description"   => "Geo Commands",
                "function"      => ""
            ],
            [
                "availableAt"   => "enable",
                "command"       => "geo show countries",
                "description"   => "Show list of countries.",
                "function"      => "geo"
            ],
            [
                "availableAt"   => "enable",
                "command"       => "geo show states",
                "description"   => "geo show states {country_code}. Show list of states of a country.",
                "function"      => "geo"
            ],
            [
                "availableAt"   => "enable",
                "command"       => "geo show cities",
                "description"   => "geo show cities {country_code} {state_code}. Show list of cities of a state.",
                "function"      => "geo"
            ],
        );

        //Set Commands
        array_push($commands,
            [
                "availableAt"   => "config",
                "command"       => "",
                "description"   => "set commands",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set status",
                "description"   => "fw set status {status}. Status options: enable/disable/monitor.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set filter",
                "description"   => "fw set filter {ip_type} {status}. Ip_type options: v4/v6, Status options: enable/disable.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set range",
                "description"   => "fw set range {range_type} {status}. Range_type options: private/reserved, Status options: enable/disable.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set default filter",
                "description"   => "fw set default filter {state}. Status options: allow/block.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw reset default filter hit count",
                "description"   => "fw reset default filter hit count. Resets default filter hit counts to 0.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set auto unblock",
                "description"   => "fw set auto unblock {minutes}. After X minutes firewall will auto unblock IP from block state. Disable the feature by setting minutes to 0.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set ip2location key",
                "description"   => "fw set ip2location key. Set key as null to remove the key",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set ip2location bin file code",
                "description"   => "fw set ip2location bin file code.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set ip2location bin access mode",
                "description"   => "fw set ip2location bin access mode.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set ip2location io key",
                "description"   => "fw set ip2location io key. Set key as null to remove the key",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw set ip2location primary lookup method",
                "description"   => "fw set ip2location primary lookup method. Lookup first in API or in downloaded BIN file? If found, secondary method is discarded.",
                "function"      => "fw"
            ]
        );

        array_push($commands,
            [
                "availableAt"   => "config",
                "command"       => "",
                "description"   => "",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "",
                "description"   => "get commands",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw get latest bin",
                "description"   => "fw get latest bin from ip2location site using API key.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw get latest geodata",
                "description"   => "fw get latest geodata from github.com/dr5hn/ repository.",
                "function"      => "fw"
            ]
        );

        //Filter Commands
        array_push($commands,
            [
                "availableAt"   => "config",
                "command"       => "",
                "description"   => "",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "",
                "description"   => "filter commands",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw filter add",
                "description"   => "fw filter add {filter_type} {address_type} {ip_address|network/subnet|country_iso2_code:region:city}. filter_type options: allow, block, monitor. address_type options: host, network, ip2location.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw filter update",
                "description"   => "fw filter update {filter_id} {filter_type}. Update filter type. filter_type options: allow, block, monitor.",
                "function"      => "fw"
            ],
            [
                "availableAt"   => "config",
                "command"       => "fw filter remove",
                "description"   => "fw filter remove {filter_id}. Remove a filter",
                "function"      => "fw"
            ]
        );

        return $commands;
    }

    protected function fwShowRun()
    {
        $this->getFirewallConfig();

        $this->terminal->addResponse('', 0, ['Firewall Details' => $this->firewallConfig]);

        return true;
    }

    protected function fwShowFilters($args = [], $filters = null, $getDefault = false)
    {
        if (!$filters) {
            $getDefault = false;

            if (isset($args[0]) && $args[0] === 'default') {
                $getDefault = true;
            }

            $totalItems = $this->firewallPackage->getFiltersCount($getDefault);

            if ($totalItems > 1000) {
                $this->terminal->addResponse('There are ' . $totalItems . ' filters in the system. Please use the fw search filter command to find the filter and it\'s ID so you can use it in show filter command.', 2);

                return false;
            }

            $filters = $this->firewallPackage->getFilters($getDefault);

            if ($filters === true) {
                $filters = $this->firewallPackage->response->getAllData();
            } else {
                $this->terminal->addResponse('Firewall has no filters!', 2);

                return true;
            }

            if (isset($filters['response']['responseCode']) && $filters['response']['responseCode'] == 0) {
                if (isset($filters['response']['responseData']['filters']) && count($filters['response']['responseData']['filters']) > 0) {
                    $filters = $filters['response']['responseData']['filters'];
                }
            }
        }

        if (isset($this->terminal->config['plugins']['auth']['class'])) {
            $this->auth = (new $this->terminal->config['plugins']['auth']['class']())->init($this->terminal);
        }

        array_walk($filters, function(&$filter) {
            if (isset($filter['updated_by']) && $filter['updated_by'] === "000") {
                $filter['updated_by'] = 'DEFAULT RULE';
            } else if (isset($filter['updated_by']) && $filter['updated_by'] != 0) {
                $account = $this->auth->getAccountById($filter['updated_by']);

                if (isset($account['profile']['full_name']) || isset($account['profile']['email'])) {
                    $filter['updated_by'] = $account['profile']['full_name'] ?? $account['profile']['email'];
                }
            }
            if (isset($filter['updated_at'])) {
                $time = Carbon::parse($filter['updated_at']);
                $filter['updated_at'] = $time->toDateTimeString();
            }
        });

        $headers =
            [
                'id', 'filter_type', 'address_type', 'address', 'ip_hits', 'hit_count', 'updated_by', 'updated_at'
            ];
        $columns =
            [
                5,15,15,50,10,10,25,25
            ];
        if ($getDefault) {
            $headers =
                [
                    'id', 'filter_type', 'address_type', 'address', 'hit_count', 'updated_by', 'updated_at'
                ];
            $columns =
                [
                    5,15,15,50,10,25,25
                ];
        }

        $this->terminal->addResponse(
            '',
            0,
            ['Filters' => $filters],
            true,
            $headers,
            $columns
        );

        return true;
    }

    protected function fwSearchFilter($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please enter address search string.', 1);

            return false;
        }

        if (strlen($args[0]) < 4) {
            $this->terminal->addResponse('Please enter address search string greater than 3 characters.', 1);

            return false;
        }

        $getDefault = false;

        if (isset($args[1]) && $args[1] === 'default') {
            $getDefault = true;
        }

        $filters = $this->firewallPackage->searchFilterByAddress($args[0], $getDefault);

        if ($filters) {
            return $this->fwShowFilters([], $filters, $getDefault);
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwShowFilter($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please enter correct id', 1);

            return false;
        }

        if ((int) $args[0] === 0) {
            $this->terminal->addResponse('Please enter correct id', 1);

            return false;
        }

        $getDefault = false;

        if (isset($args[1]) && $args[1] === 'default') {
            $getDefault = true;
        }

        $filter = $this->firewallPackage->getFilterById($args[0], true, $getDefault);

        if ($filter) {
            if ($getDefault && $filter['updated_by'] === '000') {
                $filter['updated_by'] = "DEFAULT RULE";
            }

            if (isset($filter['ips']) && $filter['ips'] > 0) {
                $ips = $filter['ips'];
                unset($filter['ips']);

                array_walk($ips, function(&$ip) use($filter) {
                    $ip['address (parent)'] = $ip['address'] . ' (' . $filter['address'] . ')';
                });
                $filter['address (parent)'] = $filter['address'];
                $filter = [$filter];
                $filter = array_merge($filter, $ips);
                $addressHeader = 'address (parent)';
            } else {
                $filter = [$filter];
                $addressHeader = 'address';
            }

            $this->terminal->addResponse(
                '',
                0,
                ['Filter' => $filter],
                true,
                [
                    'id', 'filter_type', 'address_type', $addressHeader, 'hit_count', 'updated_by', 'updated_at'
                ],
                [
                    5,15,15,50,10,25,25
                ]
            );

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetStatus($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide status', 1);

            return false;
        }

        $firewallConfig = $this->firewallPackage->setConfigStatus($args[0]);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetFilter($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide filter ip type. Options: v4/v6', 1);

            return false;
        }

        if (!isset($args[1])) {
            $this->terminal->addResponse('Please provide filter status. Options enable/disable', 1);

            return false;
        }

        $firewallConfig = $this->firewallPackage->setConfigFilter($args[0], $args[1]);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetRange($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide filter range type. Options: private/reserved', 1);

            return false;
        }

        if (!isset($args[1])) {
            $this->terminal->addResponse('Please provide filter status. Options enable/disable', 1);

            return false;
        }

        $firewallConfig = $this->firewallPackage->setConfigRange($args[0], $args[1]);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetDefaultFilter($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide default filter state. Options: allow/block', 1);

            return false;
        }

        $firewallConfig = $this->firewallPackage->setConfigDefaultFilter($args[0]);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetAutoUnblock($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide correct minutes.', 1);

            return false;
        }

        $firewallConfig = $this->firewallPackage->setConfigAutoUnblockIpMinutes((int) $args[0]);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetIp2locationKey($args)
    {
        $key = $this->terminal->inputToArray(['enter key']);

        $firewallConfig = $this->firewallPackage->setConfigIp2locationKey($key['enter key']);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetIp2locationBinFileCode($args)
    {
        $binFileCode = $this->terminal->inputToArray(
            ['bin file code'],
            [
                'bin file code' =>
                    [
                        'DB3BINIPV6','DB3LITEBINIPV6'
                    ]
            ],
            [],
            [
                'bin file code' => $this->firewallConfig['ip2location_bin_file_code']
            ]
        );

        if (!$binFileCode) {
            return true;
        }

        $firewallConfig = $this->firewallPackage->setIp2locationBinFileCode($binFileCode['bin file code']);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetIp2locationBinAccessMode($args)
    {
        $binAccessMode = $this->terminal->inputToArray(
            ['bin access mode'],
            [
                'bin access mode' =>
                    [
                        'SHARED_MEMORY', 'MEMORY_CACHE', 'FILE_IO'
                    ]
            ],
            [],
            [
                'bin access mode' => $this->firewallConfig['ip2location_bin_access_mode']
            ]
        );

        if (!$binAccessMode) {
            return true;
        }

        $firewallConfig = $this->firewallPackage->setIp2locationBinAccessMode($binAccessMode['bin access mode']);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetIp2locationIoKey($args)
    {
        $key = $this->terminal->inputToArray(['enter key']);

        $firewallConfig = $this->firewallPackage->setConfigIp2locationIoKey($key['enter key']);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwSetIp2locationPrimaryLookupMethod($args)
    {
        $primaryLookupMethod = $this->terminal->inputToArray(
            ['primary lookup method'],
            [
                'primary lookup method' =>
                    [
                        'API', 'BIN'
                    ]
            ],
            [],
            [
                'primary lookup method' => $this->firewallConfig['ip2location_primary_lookup_method']
            ],
            [
                'primary lookup method' => true
            ]
        );

        if (!$primaryLookupMethod) {
            return true;
        }

        $firewallConfig = $this->firewallPackage->setIp2locationPrimaryLookupMethod($primaryLookupMethod['primary lookup method']);

        if ($firewallConfig) {
            $this->showFirewall();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwGetLatestBin()
    {
        if (!isset($this->firewallConfig['ip2location_api_key']) ||
            (isset($this->firewallConfig['ip2location_api_key']) && $this->firewallConfig['ip2location_api_key'] == 'null')
        ) {
            $this->terminal->addResponse('Please set IP2Location API key!', 1);

            return false;
        }

        $confimation = $this->terminal->inputToArray(
            ['get latest version of bin file: ' . $this->firewallConfig['ip2location_bin_file_code']],
            [
                'get latest version of bin file: ' . $this->firewallConfig['ip2location_bin_file_code'] =>
                    [
                        'Y', 'N'
                    ]
            ]
        );

        if (!$confimation ||
            ($confimation && $confimation['get latest version of bin file: ' . $this->firewallConfig['ip2location_bin_file_code']] === 'N')
        ) {
            return true;
        }

        \cli\line('');

        $download = $this->terminal->downloadData(
                'https://www.ip2location.com/download/?token=' . $this->firewallConfig['ip2location_api_key'] . '&file=' . $this->firewallConfig['ip2location_bin_file_code'],
                fwbase_path('firewalldata/ip2locationdata/' . $this->firewallConfig['ip2location_bin_file_code'] . '.ZIP')
            );

        if ($download) {
            if ($this->terminal->trackCounter !== 0) {
                \cli\line('');
                \cli\line('%bProcessing download...%w');
                \cli\line('');
            }

            $this->firewallPackage->processDownloadedBinFile($download, $this->terminal->trackCounter);
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function geoShowCountries()
    {
        $countries = $this->firewallPackage->geoGetCountries();

        if ($countries) {
            $this->terminal->addResponse(
                '',
                0,
                ['countries' => $countries],
                true,
                ['id', 'country_code', 'name'],
                [10,20,100]
            );
        } else  {
            $this->terminal->addResponse('No countries database available. Please download database from configuration mode!', 1);
        }

        return true;
    }

    protected function geoShowStates($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide country code. Run command geo show countries to grab the code.', 1);

            return false;
        }

        $states = $this->firewallPackage->geoGetStates(strtoupper($args[0]));

        if ($states) {
            $this->terminal->addResponse(
                '',
                0,
                ['states' => $states],
                true,
                ['id', 'state_code', 'country_code', 'name'],
                [10,20,20,100]
            );
        } else  {
            $this->terminal->addResponse('No states database available. Please download database from configuration mode!', 1);
        }

        return true;
    }

    protected function geoShowCities($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide country code. Run command geo show countries to grab the code.', 1);

            return false;
        }

        if (!isset($args[1])) {
            $this->terminal->addResponse('Please provide state code. Run command geo show states {country_code} to grab the code.', 1);

            return false;
        }

        $cities = $this->firewallPackage->geoGetCities(strtoupper($args[0]), strtoupper($args[1]));

        if ($cities) {
            $this->terminal->addResponse(
                '',
                0,
                ['cities' => $cities],
                true,
                ['id', 'state_code', 'country_code', 'name'],
                [10,20,20,100]
            );
        } else  {
            $this->terminal->addResponse('No cities database available. Please download database from configuration mode!', 1);
        }

        return true;
    }

    protected function fwGetLatestGeodata()
    {
        $confimation = $this->terminal->inputToArray(
            ['get latest version of geodata'],
            [
                'get latest version of geodata' =>
                    [
                        'Y', 'N'
                    ]
            ]
        );

        if (!$confimation ||
            ($confimation && $confimation['get latest version of geodata'] === 'N')
        ) {
            return true;
        }

        \cli\line('');

        $download = $this->terminal->downloadData(
                'https://raw.githubusercontent.com/dr5hn/countries-states-cities-database/master/countries%2Bstates%2Bcities.json',
                fwbase_path('firewalldata/geodata/countries+states+cities.json')
            );

        if (true) {
            if ($this->terminal->trackCounter !== 0) {
                \cli\line('');
                \cli\line('%bProcessing download, this will take sometime...%w');
                \cli\line('');
            }

            $this->firewallPackage->processDownloadedGeodataFile($download, $this->terminal->trackCounter);
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwResetDefaultFilterHitCount()
    {
        $resetConfirmationArr = $this->terminal->inputToArray(['confirm reset'], ['confirm reset' => 'yes/no']);

        if (strtolower($resetConfirmationArr['confirm reset']) === 'yes') {
            $firewallConfig = $this->firewallPackage->resetConfigDefaultFilterHitCount();

            if ($firewallConfig) {
                $this->showFirewall();

                return true;
            }
        } else if (strtolower($resetConfirmationArr['confirm reset']) === 'no') {
            return true;
        } else {
            $this->terminal->addResponse('Unknown option entered : ' . $resetConfirmationArr['confirm reset'], 1);

            return false;
        }

        return true;
    }

    protected function fwCheckIp($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide correct ip address', 1);

            return false;
        }

        $filter = $this->firewallPackage->checkIp($args[0]);

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwShowIpDetails($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide correct ip address', 1);

            return false;
        }

        $filter = $this->firewallPackage->getIpDetailsFromIp2locationAPI($args[0]);

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwFilterAdd($args)
    {
        //Filter Type
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please enter correct filter type', 1);

            return false;
        }

        if ($args[0] !== 'allow' && $args[0] !== 'block' && $args[0] !== 'monitor') {
            $this->terminal->addResponse('Please enter correct filter type. allow/block/monitor are available filter type options. Don\'t know what ' . $args[0] . ' is...', 1);

            return false;
        }

        //Address Type
        if (!isset($args[1])) {
            $this->terminal->addResponse('Please enter correct address type', 1);

            return false;
        }

        if ($args[1] !== 'host' && $args[1] !== 'network' && $args[1] !== 'ip2location') {
            $this->terminal->addResponse('Please enter correct address type. host/network/ip2location are available address type options. Don\'t know what ' . $args[1] . ' is...', 1);

            return false;
        }

        //Address/ip2location
        if (!isset($args[2])) {
            $this->terminal->addResponse('Please enter correct address|ip2location/{country:region:city}', 1);

            return false;
        }

        if (str_contains($args[2], ':')) {
            $argsArr = $args;

            $argsArr = array_splice($argsArr, 2);

            $args[2] = join(' ', $argsArr);
        }

        $filterData['filter_type'] = $args[0];
        $filterData['address_type'] = $args[1];
        $filterData['address'] = $args[2];
        $filterData['updated_by'] = $this->terminal->getAccount()['id'] ?? 0;
        $filterData['updated_at'] = time();
        $filterData['hit_count'] = 0;

        $newFilter = $this->firewallPackage->addFilter($filterData);

        if ($newFilter) {
            $this->terminal->addResponse('Filter added successfully', 0, ['newFilter' => $newFilter]);

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwFilterUpdate($args)
    {
        if (!isset($args[0]) || !isset($args[1])) {
            $this->terminal->addResponse('Please provide filter ID and filter type', 1);

            return false;
        }

        //Filter Type
        if ($args[1] !== 'allow' && $args[1] !== 'block' && $args[1] !== 'monitor') {
            $this->terminal->addResponse('Please enter correct filter type. allow/block/monitor are available filter type options. Don\'t know what ' . $args[1] . ' is...', 1);

            return false;
        }

        $filterData['id'] = $args[0];
        $filterData['filter_type'] = $args[1];
        $filterData['updated_by'] = $this->terminal->getAccount()['id'] ?? 0;
        $filterData['updated_at'] = time();

        $updateFilter = $this->firewallPackage->updateFilter($filterData);

        if ($updateFilter) {
            $this->terminal->addResponse('Filter updated successfully', 0);

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function fwFilterRemove($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide filter ID', 1);

            return false;
        }

        $fromDefault = false;

        if (isset($args[1]) && $args[1] === 'default') {
            $fromDefault = true;
        }

        $removeFilter = $this->firewallPackage->removeFilter($args[0], $fromDefault);

        if ($removeFilter) {
            $this->terminal->addResponse('Filter removed successfully', 0);

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    public function onInstall() : object
    {
        $this->terminal->setCommandIgnoreChars(['.',':']);

        $this->terminal->config['modules']['firewall']['banner'] =
            'PHPTerminal-modules-firewall is an firewall module for PHPTerminal to manage PHPFirewall library.';

        return $this;
    }

    protected function addFirewallResponseToTerminalResponse()
    {
        $response = $this->firewallPackage->response->getAllData();

        if (isset($response['response']['responseCode']) && isset($response['response']['responseMessage'])) {
            $this->terminal->addResponse(
                $response['response']['responseMessage'],
                $response['response']['responseCode'],
                $response['response']['responseData'] ?? []
            );
        }
    }
}