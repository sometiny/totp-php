<?php

namespace Jazor\OTP;

class Uri
{
    private string $type = 'totp';
    private string $label = '';
    private string $issuer = '';
    private string $algorithm = 'sha1';
    private ?string $counter = null;
    private int $digits = 6;
    private int $period = 30;
    private string $secret = '';
    private array $label_components = [];

    public function __construct(?string $url)
    {
        if (empty($url)) return;
        $isMatch = preg_match('#^otpauth://(totp|hotp)/(.+?)\?(.+?)$#', $url, $match);

        if (!$isMatch) throw new \Exception('invalid url');

        $type = $match[1];
        $label = urldecode($match[2]);
        parse_str($match[3], $parameters);
        if (empty($parameters['secret'])) {
            throw new \Exception('secret is necessary!');
        }

        if ($type === 'hotp' && empty($parameters['counter'])) {
            throw new \Exception('counter is necessary for hotp!');
        }

        $label_components = [];
        $idx = strpos($label, ':');
        if ($idx !== false) {
            $label_components = [
                substr($label, 0, $idx),
                ltrim(substr($label, $idx), ':')
            ];
        }


        $this->type = $type;
        $this->label = $label;
        $this->label_components = $label_components;
        $this->secret = $parameters['secret'];
        $this->issuer = $parameters['issuer'] ?? '';
        $this->algorithm = $parameters['algorithm'] ?? 'sha1';
        $this->digits = $parameters['digits'] ?? 6;
        $this->counter = $parameters['counter'] ?? null;
        $this->period = $parameters['period'] ?? 30;
    }

    /**
     * @param string $type
     * @return Uri
     */
    public function setType(string $type): Uri
    {
        $this->type = $type;
        return $this;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @param string $label
     * @return Uri
     */
    public function setLabel(string $label): Uri
    {
        $this->label = $label;
        return $this;
    }

    /**
     * @return string
     */
    public function getLabel(): string
    {
        return $this->label;
    }

    /**
     * @param string $issuer
     * @return Uri
     */
    public function setIssuer(string $issuer): Uri
    {
        $this->issuer = $issuer;
        return $this;
    }

    /**
     * @return string
     */
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * @param string $algorithm
     * @return Uri
     */
    public function setAlgorithm(string $algorithm): Uri
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @param string|null $counter
     * @return Uri
     */
    public function setCounter(?string $counter): Uri
    {
        $this->counter = $counter;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getCounter(): ?string
    {
        return $this->counter;
    }

    /**
     * @param int $digits
     * @return Uri
     */
    public function setDigits(int $digits): Uri
    {
        $this->digits = $digits;
        return $this;
    }

    /**
     * @return int
     */
    public function getDigits(): int
    {
        return $this->digits;
    }

    /**
     * @param int $period
     * @return Uri
     */
    public function setPeriod(int $period): Uri
    {
        $this->period = $period;
        return $this;
    }

    /**
     * @return int
     */
    public function getPeriod(): int
    {
        return $this->period;
    }

    /**
     * @param string $secret
     * @return Uri
     */
    public function setSecret(string $secret): Uri
    {
        $this->secret = $secret;
        return $this;
    }

    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getBinarySecret(): string
    {
        return Base32::quick_decode($this->secret);
    }

    public function __toString()
    {
        $components = ['otpauth://', $this->type, '/', urlencode($this->label), '?secret=', urlencode($this->secret)];
        if($this->algorithm !== 'sha1') array_push($components, '&algorithm=', $this->algorithm);
        if (!empty($this->counter)) array_push($components, '&counter=', $this->counter);
        if($this->digits !== 6) array_push($components, '&digits=', $this->digits);
        if($this->period !== 30) array_push($components, '&period=', $this->period);
        if (!empty($this->issuer)) array_push($components, '&issuer=', urlencode($this->issuer));
        return implode('', $components);
    }

    /**
     * @return array
     */
    public function getLabelComponents(): array
    {
        return $this->label_components;
    }
}
