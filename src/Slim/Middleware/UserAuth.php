<?php
/**
 * Slim - a micro PHP 5 framework
 *
 * @author      Josh Lockhart <info@slimframework.com>
 * @copyright   2011 Josh Lockhart
 * @link        http://www.slimframework.com
 * @license     http://www.slimframework.com/license
 * @version     2.3.0
 * @package     Slim
 *
 * MIT LICENSE
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
namespace Slim\Middleware;

 /**
  * UserAuth
  *
  * This class provides an way to authenticate against a user
  * database. User information and status will be available
  * from within he app class.
  *
  * @package    Slim
  * @author     Tristan Mills
  * @since      2.3.0
  */
class UserAuth extends \Slim\Middleware
{

    /**
     * @var array
     */
    protected $settings;

    /**
     * @var array
     */
    public $info;

    /**
     * @var bool
     */
    public $signedIn = false;

    /**
     * Call
     */
    public function call() {

        $this->app->user = $this;

        $this->next->call();

    }

    /**
     * Constructor
     *
     * @param array $settings
     */
    public function __construct($settings = array()) {

        $this->settings = array_merge(array(
            'database.dsn'        => 'sqlite:slim.db',
            'database.username'   => null,
            'database.password'   => null,
            'database.options'    => array(),
            'database.pepper'     => 'pepper',
            'table'               => 'users',
            'column.group'        => '_group',
            'column.email'        => 'email',
            'column.password'     => 'password',
            'column.emailId'      => 'email_id',
            'column.registerKey'  => 'register_key',
            'column.resetKey'     => 'reset_key',
            'session.lifetime'    => '20 minutes',
            'session.path'        => '/',
            'session.domain'      => null,
            'session.secure'      => false,
            'session.httponly'    => true,
            'session.name'        => 'slim_session',
            'session.directory'   => null,
        ), $settings);

        $this->settings['session.directory'] = realpath($this->settings['session.directory']);

        $this->_init();

    }

    /**
     * _init
     *
     * .
     *
     */
    protected function _init() {

        session_name($this->settings['session.name']);

        $this->app = \Slim\Slim::getInstance();

        $sessionCookie = $this->app->request()->cookies($this->settings['session.name']);

        if (isset($sessionCookie)) {

            if ($this->settings['session.directory']) {

                session_save_path($this->settings['session.directory']);

            }

            session_set_cookie_params($this->settings['session.lifetime'], $this->settings['session.path'], $this->settings['session.domain'], $this->settings['session.secure'], $this->settings['session.httponly']);

            session_start();

        }

        if (empty($_SESSION[$this->settings['session.name']]) === false) {

            $this->info = $_SESSION[$this->settings['session.name']];

            $this->signedIn = true;

        } elseif (false) {

            //TODO: remember me

        }

    }

    /**
     * signIn
     *
     * Add auth information to the session and app instance.
     *
     * @param string $email
     */
    public function signIn($email) {

        if (session_id() === '') {

            if ($this->settings['session.directory']) {

                session_save_path($this->settings['session.directory']);

            }

            session_set_cookie_params($this->settings['session.lifetime'], $this->settings['session.path'], $this->settings['session.domain'], $this->settings['session.secure'], $this->settings['session.httponly']);

            session_start();
        }

        $info = $this->infoFromEmail($email);

        session_regenerate_id(true);

        $_SESSION[$this->settings['session.name']] = $info;

        $this->info = $info;

        $this->signedIn = true;

    }

    /**
     * signOut
     *
     * Remove auth information to the session and app instance.
     *
     */
    public function signOut() {

        session_regenerate_id(true);

        session_unset();

        session_destroy();

        setcookie($this->settings['session.name'], '', $this->settings['session.lifetime'], $this->settings['session.path'], $this->settings['session.domain'], $this->settings['session.secure'], $this->settings['session.httponly']);

        $this->info = null;

        $this->signedIn = false;

    }

    /**
     * memberOfGroup
     *
     * Compare the group given to the value in group.
     *
     * @param string $group
     */
    public function memberOfGroup($group) {

        if ($group === $this->info[$this->settings['column.group']]) {

            return true;

        } else {

            return false;

        }

    }

    /**
     * exists
     *
     * Query the database to see if the email exists.
     *
     * @param string $email
     * @param string $password
     * @return bool
     */
    public function exists($email) {

        try {

            $dbh = new \PDO($this->settings['database.dsn'], $this->settings['database.username'], $this->settings['database.password'], $this->settings['database.options']);

            $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $sql = 'SELECT * FROM ' . $this->settings['table'] . ' WHERE ' . $this->settings['column.email'] . ' = :email';

            $sth = $dbh->prepare($sql);

            $sth->bindParam(':email', $email);

            $sth->execute();

            $exists = $sth->fetch() === false ? false : true;

            $dbh = null;

            return $exists;

        } catch (\PDOException $e) {

            $this->app->error($e);

        }

    }

    /**
     * registered
     *
     * Query the database to see if the email and password match up.
     *
     * @param string $email
     * @param string $password
     * @return bool
     */
    public function registered($email, $password) {

        try {

            $dbh = new \PDO($this->settings['database.dsn'], $this->settings['database.username'], $this->settings['database.password'], $this->settings['database.options']);

            $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $sql = 'SELECT ' . $this->settings['column.password'] . ' FROM ' . $this->settings['table'] . ' WHERE ' . $this->settings['column.email'] . ' = :email';

            $sth = $dbh->prepare($sql);

            $sth->bindParam(':email', $email);

            $sth->execute();

            $hash = $sth->fetch(\PDO::FETCH_COLUMN);

            $dbh = null;

            if (password_verify($password . $this->settings['database.pepper'], $hash)) {

                return true;

            } else {

                return false;

            }

        } catch (\PDOException $e) {

            $this->app->error($e);

        }

    }

    /**
     * confirmed
     *
     * Query the database to see if the email exists with an empty auth key.
     *
     * @param string $email
     * @return bool
     */
    public function confirmed($email) {

        try {

            $dbh = new \PDO($this->settings['database.dsn'], $this->settings['database.username'], $this->settings['database.password'], $this->settings['database.options']);

            $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $sql = 'SELECT * FROM ' . $this->settings['table'] . ' WHERE ' . $this->settings['column.email'] . ' = :email AND ' . $this->settings['column.registerKey'] . ' IS NULL';

            $sth = $dbh->prepare($sql);

            $sth->bindParam(':email', $email);

            $sth->execute();

            $confirmed = $sth->fetch() === false ? false : true;

            $dbh = null;

            return $confirmed;

        } catch (\PDOException $e) {

            $this->app->error($e);

        }

    }

    /**
     * info
     *
     * Query the database for data based on the given email
     *
     * @param string $email
     * @return array
     */
    public function infoFromEmail($email) {

        try {

            $dbh = new \PDO($this->settings['database.dsn'], $this->settings['database.username'], $this->settings['database.password'], $this->settings['database.options']);

            $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $sql = 'SELECT * FROM ' . $this->settings['table'] . ' WHERE ' . $this->settings['column.email'] . ' = :email';

            $sth = $dbh->prepare($sql);

            $sth->bindParam(':email', $email);

            $sth->execute();

            $info = $sth->fetch(\PDO::FETCH_ASSOC);

            $dbh = null;

            return $info;

        } catch (\PDOException $e) {

            $this->app->error($e);

        }

    }

    /**
     * infoFromAuthId
     *
     * Query the database for data based on the given emailId
     *
     * @param string $email
     * @return array
     */
    public function infoFromAuthId($emailId) {

        try {

            $dbh = new \PDO($this->settings['database.dsn'], $this->settings['database.username'], $this->settings['database.password'], $this->settings['database.options']);

            $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $sql = 'SELECT * FROM ' . $this->settings['table'] . ' WHERE ' . $this->settings['column.emailId'] . ' = :emailId';

            $sth = $dbh->prepare($sql);

            $sth->bindParam(':emailId', $emailId);

            $sth->execute();

            $info = $sth->fetch(\PDO::FETCH_ASSOC);

            $dbh = null;

            return $info;

        } catch (\PDOException $e) {

            $this->app->error($e);

        }

    }

    /**
     * register
     *
     * Add a new user to the database.
     *
     * @param string $group
     * @param string $email
     * @param string $password
     * @param string $emailId
     * @param string $registerKey
     * @return bool
     */
    public function register($group, $email, $password, $emailId, $registerKey) {

        $password = password_hash($password . $this->settings['database.pepper'], PASSWORD_DEFAULT);

        try {

            $dbh = new \PDO($this->settings['database.dsn'], $this->settings['database.username'], $this->settings['database.password'], $this->settings['database.options']);

            $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $sql = 'INSERT INTO ' . $this->settings['table'] . ' (' . $this->settings['column.group'] . ', ' . $this->settings['column.email'] . ', ' . $this->settings['column.password'] . ', ' . $this->settings['column.emailId'] . ', ' . $this->settings['column.registerKey'] . ', ' . $this->settings['column.resetKey'] . ') VALUES (:group, :email, :password, :emailId, :registerKey, :resetKey)';

            $sth = $dbh->prepare($sql);

            $sth->bindParam(':group', $group);
            $sth->bindParam(':email', $email);
            $sth->bindParam(':password', $password);
            $sth->bindParam(':emailId', $emailId);
            $sth->bindParam(':registerKey', $registerKey);
            $sth->bindParam(':resetKey', $resetKey);

            $registered = $sth->execute();

            $dbh = null;

            return $registered;

        } catch (\PDOException $e) {

            $this->app->error($e);

        }

    }

    /**
     * authenticate
     *
     * .
     *
     * @param string $emailId
     * @param string $registerKey
     * @return bool
     */
    public function authenticate($emailId, $registerKey) {

        try {

            $dbh = new \PDO($this->settings['database.dsn'], $this->settings['database.username'], $this->settings['database.password'], $this->settings['database.options']);

            $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $sql = 'UPDATE ' . $this->settings['table'] . ' SET ' . $this->settings['column.registerKey'] . ' = NULL WHERE ' . $this->settings['column.emailId'] . ' = :emailId AND ' . $this->settings['column.registerKey'] . ' = :registerKey';

            $sth = $dbh->prepare($sql);

            $sth->bindParam(':emailId', $emailId);

            $sth->bindParam(':registerKey', $registerKey);

            $authenticated = $sth->execute();

            $dbh = null;

            return $authenticated;

        } catch (\PDOException $e) {

            $this->app->error($e);

        }
    }

    /**
     * authenticate
     *
     * .
     *
     * @param string $email
     * @param string $resetKey
     * @return bool
     */
    public function resetPasswordPrep($email, $resetKey) {

        try {

            $dbh = new \PDO($this->settings['database.dsn'], $this->settings['database.username'], $this->settings['database.password'], $this->settings['database.options']);

            $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $sql = 'UPDATE ' . $this->settings['table'] . ' SET ' . $this->settings['column.resetKey'] . ' = :resetKey WHERE ' . $this->settings['column.email'] . ' = :email';

            $sth = $dbh->prepare($sql);

            $sth->bindParam(':email', $email);
            $sth->bindParam(':resetKey', $resetKey);

            $result = $sth->execute();

            $dbh = null;

            return $result;

        } catch (\PDOException $e) {

            $this->app->error($e);

        }

    }



    public function updatePassword($password, $emailId, $resetKey) {

        $password = password_hash($password . $this->settings['database.pepper'], PASSWORD_DEFAULT);

        try {

            $dbh = new \PDO($this->settings['database.dsn'], $this->settings['database.username'], $this->settings['database.password'], $this->settings['database.options']);

            $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $sql = 'UPDATE ' . $this->settings['table'] . ' SET password = :password, ' . $this->settings['column.resetKey'] . ' = NULL WHERE ' . $this->settings['column.emailId'] . ' = :emailId AND ' . $this->settings['column.resetKey'] . ' = :resetKey';

            $sth = $dbh->prepare($sql);

            $sth->bindParam(':password', $password);
            $sth->bindParam(':emailId', $emailId);
            $sth->bindParam(':resetKey', $resetKey);

            $updated = $sth->execute();

            $dbh = null;

            return $updated;

        } catch (\PDOException $e) {

            $this->app->error($e);

        }

    }

}

