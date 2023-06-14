<?php

namespace App\Tests\Controller\Api;

use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class UserControllerTest extends WebTestCase
{

    /**
     * Test fetching informations for profile page
     *
     */
    public function testGetInformationForProfile(): void
    {

        //creating a user
        $client = static::createClient();
        $userRepository = static::getContainer()->get(UserRepository::class);
        // retrieve the test user
        $testUser = $userRepository->findOneByEmail('gilles.margaret@chevalier.com');
        // simulate $testUser being logged in
        $client->loginUser($testUser);
        //route to test
        $crawler = $client->request('GET', '/api/secure/users/profile');

        $this->assertResponseIsSuccessful();
    }

    /**
     * Test route to create an user   
     */
    public function testCreateUser(): void
    {
        //create a user
        $client = static::createClient();

        //create data for user
        $email = 'jjon@gmail.com';
        $password = 'jean';
        $lastname = 'louis';
        $firstname = 'jean';
        $roles = ['ROLE_ARTIST'];

        //putting data in array
        $data = [
            'email' => $email,
            'password' => $password,
            'lastname' => $lastname,
            'firstname' => $firstname,
            'roles' => $roles
        ];

        //route to test with data
        $crawler = $client->request('POST', '/api/users/new', [], [], [], json_encode($data));

        //status 201 if created
        $this->assertResponseStatusCodeSame(201);
    }
}
