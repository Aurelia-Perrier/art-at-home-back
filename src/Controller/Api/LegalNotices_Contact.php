<?php

namespace App\Controller\Api;

use App\Repository\ContactRepository;
use App\Repository\LegalNoticesRepository;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class LegalNotices_Contact extends AbstractController
{
    /**
     * Get legal notices
     *
     * @param LegalNoticesRepository $legalNoticesRepository
     * @return Response
     * @Route ("/api/legal-notices", name="app_api_legale_notices", methods={"GET"})
     */
    public function getLegalNotices(LegalNoticesRepository $legalNoticesRepository) : Response
    {

        $legalNotices = $legalNoticesRepository->findAll();

        return $this->json(
            $legalNotices,
            Response::HTTP_OK,
            [],
            ['groups' => 'get_legal_notices']
        );
    }

    /**
     * Get contact
     *
     * @param ContactRepository $contactRepository
     * @return Response
     * @Route ("api/contact", name="app_api_contact", methods={"GET"})
     */
    public function getContact(ContactRepository $contactRepository) : Response
    {
        $contact = $contactRepository->findAll();

        return $this->json(
            $contact,
            Response::HTTP_OK,
            [],
            ['groups' => 'get_contact']
        );
    }
}