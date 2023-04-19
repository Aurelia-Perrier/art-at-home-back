<?php

namespace App\Controller\Back;

use App\Entity\Artwork;
use App\Form\ArtworkType;
use App\Repository\ArtworkRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

/**
 * @Route("/artwork")
 */
class ArtworkController extends AbstractController
{
    /**
     * @Route("/", name="app_artwork_index", methods={"GET"})
     */
    public function index(ArtworkRepository $artworkRepository): Response
    {
        return $this->render('artwork/index.html.twig', [
            'artworks' => $artworkRepository->findBy(['status' => true],['id' => 'DESC']),
        ]);
    }

    /**
     * Displaying artworks with status false
     *
     * @Route ("/validation-waiting", name="app_validation_waiting")
     */
    public function validatePage(ArtworkRepository $artworkRepository) : Response
    {
        return $this->render('artwork/validation.html.twig',
        [
            'artworks' => $artworkRepository->findBy(['status' => false])
        ]);
    }

    /**
     * @Route("/new", name="app_artwork_new", methods={"GET", "POST"})
     */
    public function new(Request $request, ArtworkRepository $artworkRepository): Response
    {
        $artwork = new Artwork();
        $form = $this->createForm(ArtworkType::class, $artwork);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $artworkRepository->add($artwork, true);

            return $this->redirectToRoute('app_artwork_index', [], Response::HTTP_SEE_OTHER);
        }

        return $this->renderForm('artwork/new.html.twig', [
            'artwork' => $artwork,
            'form' => $form,
        ]);
    }

    /**
     * @Route("/{id}", name="app_artwork_show", methods={"GET"})
     */
    public function show(Artwork $artwork): Response
    {
        return $this->render('artwork/show.html.twig', [
            'artwork' => $artwork,
        ]);
    }

    /**
     * @Route("/{id}/edit", name="app_artwork_edit", methods={"GET", "POST"})
     */
    public function edit(Request $request, Artwork $artwork, ArtworkRepository $artworkRepository): Response
    {
        $form = $this->createForm(ArtworkType::class, $artwork);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $artworkRepository->add($artwork, true);

            return $this->redirectToRoute('app_artwork_index', [], Response::HTTP_SEE_OTHER);
        }

        return $this->renderForm('artwork/edit.html.twig', [
            'artwork' => $artwork,
            'form' => $form,
        ]);
    }

    /**
     * @Route("/{id}", name="app_artwork_delete", methods={"POST"})
     */
    public function delete(Request $request, Artwork $artwork, ArtworkRepository $artworkRepository): Response
    {
        if ($this->isCsrfTokenValid('delete'.$artwork->getId(), $request->request->get('_token'))) {
            $artworkRepository->remove($artwork, true);
        }

        return $this->redirectToRoute('app_artwork_index', [], Response::HTTP_SEE_OTHER);
    }

    /**
     * validate an artwork
     * @Route("/artworks/{id}/validate", name ="app_artwork_validate", methods={"POST"})
     */
    public function validate(EntityManagerInterface $entityManager, Artwork $artwork) : Response
    {
        
        $artwork->setStatus(1);
        $entityManager->persist($artwork);
        $entityManager->flush();
        return $this->redirectToRoute('app_validation_waiting');
    }
}
