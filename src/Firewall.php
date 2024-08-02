<?php

namespace PHPTerminalModulesFirewall;

use Carbon\Carbon;
use JasonGrimes\Paginator;
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
                    "command"       => "show run",
                    "description"   => "Show firewall module running configuration",
                    "function"      => "show"
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "show filters",
                    "description"   => "Show firewall filters. show filters {limit} {page}, will set page limit. Use the keyword default in the end to search default filters data storage.",
                    "function"      => "show"
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "show filter",
                    "description"   => "show filter {id}",
                    "function"      => "show"
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "search filter",
                    "description"   => "search filter {address}. Ex: fw search filter 10.0.0. This command performs a like search, so anything with 10.0.0 will be searched in addresses. Use the keyword default in the end to search default filters data storage.",
                    "function"      => "search"
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
                    "command"       => "check ip",
                    "description"   => "check ip {address}. Check state of an ip address, if it is being blocked/allowed/monitored by the firewall. Additionally if you are checking ip using ip2location, you can add an extra argument to override the default primary method. If method is API, you can enter keyword bin to override primary method.",
                    "function"      => "check"
                ],
            ];

        if ($this->firewallConfig &&
            (isset($this->firewallConfig['ip2location_io_api_key']) && $this->firewallConfig['ip2location_io_api_key'] !== '') ||
            (isset($this->firewallConfig['ip2location_api_key']) && $this->firewallConfig['ip2location_api_key'] !== '' && $this->firewallConfig['ip2location_bin_download_date'])
        ) {
            //grab ip details from ip2location.io api
            array_push($commands,
                [
                    "availableAt"   => "enable",
                    "command"       => "show ip details",
                    "description"   => "show ip details {address}. Get ip details from ip2location io API and BIN file if downloaded. Default lookup method is API, if you enter keyword bin it will lookup in bin file first.",
                    "function"      => "show"
                ]
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
                "command"       => "show geo countries",
                "description"   => "Show list of countries.",
                "function"      => "show"
            ],
            [
                "availableAt"   => "enable",
                "command"       => "show geo states",
                "description"   => "show geo states {country_code}. Show list of states of a country.",
                "function"      => "show"
            ],
            [
                "availableAt"   => "enable",
                "command"       => "show geo cities",
                "description"   => "show geo cities {country_code} {state_code}. Show list of cities of a state.",
                "function"      => "show"
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
                "command"       => "set status",
                "description"   => "set status {status}. Status options: enable/disable/monitor.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "set filter",
                "description"   => "set filter {ip_type} {status}. Ip_type options: v4/v6, Status options: enable/disable.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "set range",
                "description"   => "set range {range_type} {status}. Range_type options: private/reserved, Status options: enable/disable.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "",
                "description"   => "",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "set default filter",
                "description"   => "set default filter {state}. Status options: allow/block.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "reset default filter hit count",
                "description"   => "reset default filter hit count. Resets default filter hit counts to 0.",
                "function"      => "reset"
            ],
            [
                "availableAt"   => "config",
                "command"       => "",
                "description"   => "",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "set auto unblock",
                "description"   => "set auto unblock {minutes}. After X minutes firewall will auto unblock IP from block state. Disable the feature by setting minutes to 0.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "set auto indexing",
                "description"   => "set auto indexing {status}. Status options: enable/disable.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "",
                "description"   => "",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "set ip2location key",
                "description"   => "set ip2location key. Set key as null to remove the key",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "set ip2location bin file code",
                "description"   => "set ip2location bin file code.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "set ip2location bin access mode",
                "description"   => "set ip2location bin access mode.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "set ip2location proxy bin file code",
                "description"   => "set ip2location proxy bin file code.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "set ip2location proxy bin access mode",
                "description"   => "set ip2location proxy bin access mode.",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "set ip2location io key",
                "description"   => "set ip2location io key. Set key as null to remove the key",
                "function"      => "set"
            ],
            [
                "availableAt"   => "config",
                "command"       => "set ip2location primary lookup method",
                "description"   => "set ip2location primary lookup method. Lookup first in API or in downloaded BIN file? If found, secondary method is discarded.",
                "function"      => "set"
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
                "command"       => "filter add",
                "description"   => "filter add {filter_type} {address_type} {ip_address|network/subnet|country_iso2_code:region:city}. filter_type options: allow, block, monitor. address_type options: host, network, ip2location.",
                "function"      => "filter"
            ],
            [
                "availableAt"   => "config",
                "command"       => "filter update",
                "description"   => "filter update {filter_id} {filter_type}. Update filter type. filter_type options: allow, block, monitor.",
                "function"      => "filter"
            ],
            [
                "availableAt"   => "config",
                "command"       => "filter remove",
                "description"   => "filter remove {filter_id} {default}. Remove a filter from main filters. Add default keyword to remove from default data store.",
                "function"      => "filter"
            ],
            [
                "availableAt"   => "config",
                "command"       => "filter move",
                "description"   => "filter move {filter_id}. Move a filter from default store to main data store.",
                "function"      => "filter"
            ]
        );

        //Maintenance Commands
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
                "description"   => "maintenance commands",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "get latest ip2location bin",
                "description"   => "get latest ip2location bin from ip2location site using API key.",
                "function"      => "get"
            ],
            [
                "availableAt"   => "config",
                "command"       => "get latest ip2location proxy bin",
                "description"   => "get latest ip2location proxy bin from ip2location site using API key.",
                "function"      => "get"
            ],
            [
                "availableAt"   => "config",
                "command"       => "get latest geodata",
                "description"   => "get latest geodata from github.com/dr5hn/ repository.",
                "function"      => "get"
            ],
            [
                "availableAt"   => "config",
                "command"       => "",
                "description"   => "",
                "function"      => ""
            ],
            [
                "availableAt"   => "config",
                "command"       => "filters reindex",
                "description"   => "filters reindex {force} {norebuild}. Reindexes all host filters. Force keyword deletes all previous index and regenerates the index. Norebuld keyword will not regenerate index after delete.",
                "function"      => "filters"
            ],
            [
                "availableAt"   => "config",
                "command"       => "filters reset cache",
                "description"   => "filters reset cache. Reset filters database cache.",
                "function"      => "filters"
            ]
        );

        return $commands;
    }

    protected function showRun()
    {
        $this->getFirewallConfig();

        $this->terminal->addResponse('', 0, ['Firewall Details' => $this->firewallConfig]);

        return true;
    }

    protected function showFilters($args = [], $filters = null, $getDefault = false)
    {
        if (in_array('default', $args)) {
            if (isset($args[1]) && ((int) $args[1] === 0 || (int) $args[1] > 500)) {
                $this->terminal->addResponse('Limit value should be a number. Please provide correct value. Max is 500.', 1);

                return true;
            }

            if (isset($args[2]) && (int) $args[2] === 0) {
                $this->terminal->addResponse('Page number value should be a number. Please provide correct value!', 1);

                return true;
            }
        } else {
            if (isset($args[0]) && ((int) $args[0] === 0 || (int) $args[0] > 500)) {
                $this->terminal->addResponse('Limit value should be a number. Please provide correct value. Max is 500.', 1);

                return true;
            }

            if (isset($args[1]) && (int) $args[1] === 0) {
                $this->terminal->addResponse('Page number value should be a number. Please provide correct value!', 1);

                return true;
            }
        }

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
                } else {
                    $this->terminal->addResponse('Firewall has no filters!', 2);

                    return true;
                }
            }
        } else {
            $totalItems = count($filters);
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

        if (!$getDefault) {//filters may vary as we do not show hosts that have parents.
            $totalItems = count($filters);
        }

        //We create pagination for the items.
        if (in_array('default', $args)) {
            $itemsPerPage = $args[1] ?? 20;
            $currentPage = $args[2] ?? 1;
        } else {
            $itemsPerPage = $args[0] ?? 20;
            $currentPage = $args[1] ?? 1;
        }

        $paginator = new Paginator((int) $totalItems, (int) $itemsPerPage, (int) $currentPage);
        if ($paginator->getNumPages() > 3) {
            $paginator->setMaxPagesToShow($paginator->getNumPages());
        }

        $pages = $paginator->getPages();
        //The package paginator is designed to show minimum 3 pages worth of data, which is quite weird.
        //We have to add a dummy array to pages, so that the while look will work once.
        if (count($pages) === 0) {
            $pages[0] = [];
        }

        $filters = array_chunk($filters, $itemsPerPage);

        $pageCounter = $paginator->getCurrentPage() - 1;

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

        while (isset($pages[$pageCounter])) {
            $rows = $filters[$pageCounter];

            array_walk($rows, function(&$row) use ($headers, $getDefault) {
                if (key_exists('parent_id', $row)) {
                    unset($row['parent_id']);
                }
                $row = array_replace(array_flip($headers), $row);
                $row = array_values($row);
            });

            $table = new \cli\Table();
            $headersUpperCase = [];
            array_walk($headers, function($header) use(&$headersUpperCase) {
                array_push($headersUpperCase, strtoupper($header));
            });
            $table->setHeaders($headersUpperCase);
            $table->setRows($rows);
            $table->setRenderer(new \cli\table\Ascii($columns));
            $table->display();

            $lastpage = false;
            $rowsCount = count($rows);
            if (($pageCounter + 1) === count($pages)) {
                $rowsCounter = $totalItems;
                $lastpage = true;
            } else {
                $rowsCounter = ($rowsCount * ($pageCounter + 1));
            }
            \cli\line('%cShowing record : ' . $rowsCounter . '/' . $totalItems . '. Page : ' . ($pageCounter + 1) . '/' . count($pages) . '. ');
            if ($lastpage) {
                \cli\line('%w');
                return true;
            }
            \cli\line('%bHit space bar or n for next page, p for previous page, q to quit%w' . PHP_EOL);

            readline_callback_handler_install("", function () {});

            while (true) {
                $input = stream_get_contents(STDIN, 1);

                if (ord($input) == 32 || ord($input) == 110 || ord($input) == 78) {//Next space or n
                    $pageCounter++;

                    break;
                } else if (ord($input) == 112 || ord($input) == 80) {//Previous
                    $pageCounter--;

                    break;
                } else if (ord($input) == 113 || ord($input) == 81) {
                    readline_callback_handler_remove();
                    return true;
                }
            }

            readline_callback_handler_remove();
        }

        return true;
    }

    protected function searchFilter($args)
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
        if (in_array('default', $args)) {
            $getDefault = true;

            if (isset($args[2]) && ((int) $args[2] === 0 || (int) $args[2] > 500)) {
                $this->terminal->addResponse('Limit value should be a number. Please provide correct value. Max is 500', 1);

                return true;
            }

            if (isset($args[3]) && (int) $args[3] === 0) {
                $this->terminal->addResponse('Page number value should be a number. Please provide correct value!', 1);

                return true;
            }
        } else {
            if (isset($args[1]) && ((int) $args[1] === 0 || (int) $args[1] > 500)) {
                $this->terminal->addResponse('Limit value should be a number. Please provide correct value. Max is 500', 1);

                return true;
            }

            if (isset($args[2]) && (int) $args[2] === 0) {
                $this->terminal->addResponse('Page number value should be a number. Please provide correct value!', 1);

                return true;
            }
        }

        $filters = $this->firewallPackage->searchFilterByAddress($args[0], $getDefault);

        if ($filters) {
            unset($args[0]);
            $args = array_values($args);

            return $this->showFilters($args, $filters, $getDefault);
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function showFilter($args)
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

            $time = Carbon::parse($filter['updated_at']);
            $filter['updated_at'] = $time->toDateTimeString();

            if (isset($filter['ips']) && $filter['ips'] > 0) {
                $ips = $filter['ips'];
                unset($filter['ips']);

                array_walk($ips, function(&$ip) use($filter) {
                    $ip['address (parent)'] = $ip['address'] . ' (' . $filter['address'] . ')';
                    $time = Carbon::parse($ip['updated_at']);
                    $ip['updated_at'] = $time->toDateTimeString();
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

    protected function setStatus($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide status', 1);

            return false;
        }

        $firewallConfig = $this->firewallPackage->setConfigStatus($args[0]);

        if ($firewallConfig) {
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setFilter($args)
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
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setRange($args)
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
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setDefaultFilter($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide default filter state. Options: allow/block', 1);

            return false;
        }

        $firewallConfig = $this->firewallPackage->setConfigDefaultFilter($args[0]);

        if ($firewallConfig) {
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setAutoUnblock($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide correct minutes.', 1);

            return false;
        }

        $firewallConfig = $this->firewallPackage->setConfigAutoUnblockIpMinutes((int) $args[0]);

        if ($firewallConfig) {
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setAutoIndexing($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide default filter state. Options: enable/disable', 1);

            return false;
        }

        $firewallConfig = $this->firewallPackage->setAutoIndexing($args[0]);

        if ($firewallConfig) {
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setIp2locationKey($args)
    {
        $key = $this->terminal->inputToArray(['enter key']);

        $firewallConfig = $this->firewallPackage->setConfigIp2locationKey($key['enter key']);

        if ($firewallConfig) {
            $this->terminal->getAllCommands();

            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setIp2locationBinFileCode($args)
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
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setIp2locationBinAccessMode($args)
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
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setIp2locationProxyBinFileCode($args)
    {
        $proxyBinFileCode = $this->terminal->inputToArray(
            ['proxy bin file code'],
            [
                'proxy bin file code' =>
                    [
                        'PX3BIN','PX3LITEBIN'
                    ]
            ],
            [],
            [
                'proxy bin file code' => $this->firewallConfig['ip2location_proxy_bin_file_code']
            ]
        );

        if (!$proxyBinFileCode) {
            return true;
        }

        $firewallConfig = $this->firewallPackage->setIp2locationProxyBinFileCode($proxyBinFileCode['proxy bin file code']);

        if ($firewallConfig) {
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setIp2locationProxyBinAccessMode($args)
    {
        $proxyBinAccessMode = $this->terminal->inputToArray(
            ['proxy bin access mode'],
            [
                'proxy bin access mode' =>
                    [
                        'SHARED_MEMORY', 'MEMORY_CACHE', 'FILE_IO'
                    ]
            ],
            [],
            [
                'proxy bin access mode' => $this->firewallConfig['ip2location_proxy_bin_access_mode']
            ]
        );

        if (!$proxyBinAccessMode) {
            return true;
        }

        $firewallConfig = $this->firewallPackage->setIp2locationProxyBinAccessMode($proxyBinAccessMode['proxy bin access mode']);

        if ($firewallConfig) {
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setIp2locationIoKey($args)
    {
        $key = $this->terminal->inputToArray(['enter key']);

        $firewallConfig = $this->firewallPackage->setConfigIp2locationIoKey($key['enter key']);

        if ($firewallConfig) {
            $this->showRun();

            $this->terminal->getAllCommands();//Reset commands list to show/hide show ip details command.

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function setIp2locationPrimaryLookupMethod($args)
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
            $this->showRun();

            return true;
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function getLatestIp2locationBin()
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
                $this->firewallPackage->ip2location->dataPath . '/' . $this->firewallConfig['ip2location_bin_file_code'] . '.ZIP'
            );

        if ($download) {
            if ($this->terminal->trackCounter !== 0) {
                \cli\line('');
                \cli\line('%bProcessing download...%w');
                \cli\line('');
            }

            $this->firewallPackage->ip2location->processDownloadedBinFile($download, $this->terminal->trackCounter);

            $this->terminal->getAllCommands();
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function getLatestIp2locationProxyBin()
    {
        if (!isset($this->firewallConfig['ip2location_api_key']) ||
            (isset($this->firewallConfig['ip2location_api_key']) && $this->firewallConfig['ip2location_api_key'] == 'null')
        ) {
            $this->terminal->addResponse('Please set IP2Location API key!', 1);

            return false;
        }

        $confimation = $this->terminal->inputToArray(
            ['get latest version of proxy bin file: ' . $this->firewallConfig['ip2location_proxy_bin_file_code']],
            [
                'get latest version of proxy bin file: ' . $this->firewallConfig['ip2location_proxy_bin_file_code'] =>
                    [
                        'Y', 'N'
                    ]
            ]
        );

        if (!$confimation ||
            ($confimation && $confimation['get latest version of proxy bin file: ' . $this->firewallConfig['ip2location_proxy_bin_file_code']] === 'N')
        ) {
            return true;
        }

        \cli\line('');

        $download = $this->terminal->downloadData(
                'https://www.ip2location.com/download/?token=' . $this->firewallConfig['ip2location_api_key'] . '&file=' . $this->firewallConfig['ip2location_proxy_bin_file_code'],
                $this->firewallPackage->ip2location->dataPath . '/' . $this->firewallConfig['ip2location_proxy_bin_file_code'] . '.ZIP'
            );

        if ($download) {
            if ($this->terminal->trackCounter !== 0) {
                \cli\line('');
                \cli\line('%bProcessing download...%w');
                \cli\line('');
            }

            $this->firewallPackage->ip2location->processDownloadedBinFile($download, $this->terminal->trackCounter, true);

            $this->terminal->getAllCommands();
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function showGeoCountries()
    {
        $countries = $this->firewallPackage->geo->geoGetCountries();

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

    protected function showGeoStates($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide country code. Run command geo show countries to grab the code.', 1);

            return false;
        }

        $states = $this->firewallPackage->geo->geoGetStates(strtoupper($args[0]));

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

    protected function showGeoCities($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide country code. Run command geo show countries to grab the code.', 1);

            return false;
        }

        if (!isset($args[1])) {
            $this->terminal->addResponse('Please provide state code. Run command geo show states {country_code} to grab the code.', 1);

            return false;
        }

        $cities = $this->firewallPackage->geo->geoGetCities(strtoupper($args[0]), strtoupper($args[1]));

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

    protected function getLatestGeodata()
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
                $this->firewallPackage->geo->dataPath . '/countries+states+cities.json'
            );

        if (true) {
            if ($this->terminal->trackCounter !== 0) {
                \cli\line('');
                \cli\line('%bProcessing download, this will take sometime...%w');
                \cli\line('');
            }

            $this->firewallPackage->geo->processDownloadedGeodataFile($download, $this->terminal->trackCounter);
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function resetDefaultFilterHitCount()
    {
        $resetConfirmationArr = $this->terminal->inputToArray(['confirm reset'], ['confirm reset' => ['Y', 'N']]);

        if ($resetConfirmationArr['confirm reset'] === 'Y') {
            $firewallConfig = $this->firewallPackage->resetConfigDefaultFilterHitCount();

            if ($firewallConfig) {
                $this->showRun();

                return true;
            }
        } else if ($resetConfirmationArr['confirm reset'] === 'N') {
            return true;
        } else {
            $this->terminal->addResponse('Unknown option entered : ' . $resetConfirmationArr['confirm reset'], 1);

            return false;
        }

        return true;
    }

    protected function checkIp($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide correct ip address', 1);

            return false;
        }

        $lookupMethods = null;

        if (isset($args[1])) {
            $args[1] = strtolower($args[1]);

            $lookupMethods[0] = $this->firewallConfig['ip2location_primary_lookup_method'];

            if ($args[1] === 'bin') {
                $lookupMethods[0] = strtoupper($args[1]);
                $lookupMethods[1] = 'API';
            } else {
                $lookupMethods[0] = 'API';
                $lookupMethods[1] = 'BIN';
            }
        }

        try {
            $this->firewallPackage->checkIp($args[0], $lookupMethods);
        } catch (\throwable $e) {
            \cli\line('%r' . $e->getMessage() . '%w');

            return true;
        }

        \cli\line('');
        \cli\line('%b' . $this->firewallPackage->getProcessedMicroTimers() . '%w');

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function showIpDetails($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide correct ip address', 1);

            return false;
        }

        $using = ['API', 'BIN'];
        if (isset($args[1])) {
            $args[1] = strtolower($args[1]);

            if ($args[1] === 'bin') {
                $using = ['BIN', 'API'];
            }
        }

        foreach ($using as $use) {
            $lookupMethod = 'getIpDetailsFromIp2location' . $use;

            $response = $this->firewallPackage->ip2location->$lookupMethod($args[0]);

            if ($response) {
                break;
            }
        }

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function filterAdd($args)
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

    protected function filterUpdate($args)
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

    protected function filterRemove($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide filter ID', 1);

            return false;
        }

        $fromDefault = false;

        if (isset($args[1]) && strtolower($args[1]) === 'default') {
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

    protected function filterMove($args)
    {
        if (!isset($args[0])) {
            $this->terminal->addResponse('Please provide filter ID', 1);

            return false;
        }

        $this->firewallPackage->moveFilter($args[0]);

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function filtersReindex($args = [])
    {
        $force = false;

        if (isset($args[0]) && strtolower($args[0]) === 'force') {
            $force = true;
        }

        $norebuild = false;
        if (isset($args[1]) && strtolower($args[1]) === 'norebuild') {
            $norebuild = true;
        }

        $this->firewallPackage->indexes->reindexFilters($force, $norebuild);

        $this->addFirewallResponseToTerminalResponse();

        return true;
    }

    protected function filtersResetCache()
    {
        $this->firewallPackage->resetFiltersCache();

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