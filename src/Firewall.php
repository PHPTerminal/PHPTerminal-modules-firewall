<?php

namespace PHPTerminalModulesFirewall;

use PHPFirewall\Firewall as PHPFirewallFirewall;
use PHPTerminal\Modules;
use PHPTerminal\Terminal;

class Firewall extends Modules
{
    protected $terminal;

    protected $command;

    protected $firewallPackage;

    public function init(Terminal $terminal = null, $command) : object
    {
        $this->terminal = $terminal;

        $this->command = $command;

        $this->firewallPackage = new PHPFirewallFirewall;

        return $this;
    }

    public function getCommands() : array
    {
        return
            [
                [
                    "availableAt"   => "enable",
                    "command"       => "show firewall",
                    "description"   => "Show firewall modules.",
                    "function"      => "show"
                ],
                [
                    "availableAt"   => "enable",
                    "command"       => "show filters",
                    "description"   => "Show firewall filters",
                    "function"      => "show"
                ],
                [
                    "availableAt"   => "config",
                    "command"       => "filter addipv4",
                    "description"   => "filter addipv4 {state} {type} {ip address/network/region details}. State options: allow, block, monitor. Type options: host, network, region.",
                    "function"      => "filter"
                ]
            ];
    }

    protected function showFirewall()
    {
        $firewall = $this->firewallPackage->getFirewallConfig();

        if (isset($firewall['response']['responseCode']) && $firewall['response']['responseCode'] == 0) {
            $this->terminal->addResponse('', 0, ['Firewall Details' => $firewall['response']['responseData']]);

            return true;
        }

        $this->terminal->addResponse('Error retrieving firewall details!', 1);

        return false;
    }

    protected function showFilters()
    {
        $filters = $this->firewallPackage->getFilters();

        if (isset($filters['response']['responseCode']) && $filters['response']['responseCode'] == 0) {
            if (isset($filters['response']['responseData']['filters']) && count($filters['response']['responseData']['filters']) > 0) {
                $this->terminal->addResponse('', 0, ['Firewall Details' => $filters['response']['responseData']]);
            } else  {
                $this->terminal->addResponse('Firewall has no filters!', 2);
            }

            return true;
        }

        $this->terminal->addResponse('Error retrieving firewall filters!', 1);

        return false;
    }

    protected function filterAddipv4($args)
    {
        var_dump($args);

        return true;
    }

    public function onInstall() : object
    {
        $this->terminal->config['modules']['firewall']['banner'] = 'PHPTerminal-modules-firewall is an firewall module for PHPTerminal to manage PHPFirewall library.';

        return $this;
    }
}