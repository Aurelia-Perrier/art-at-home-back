<?php

namespace App\EventListener;


use App\Entity\User;
use App\Service\MySlugger;
use Doctrine\Persistence\Event\LifecycleEventArgs;

/**
 * Slugify the title of an entity when persist
 */
class AutoSluggerCreate
{

    private $slugger;

    public function __construct(MySlugger $slugger)
    {
        $this->slugger = $slugger;
    }

    public function prePersist(LifecycleEventArgs $args): void
    {
        //fetching entity
        $entity = $args->getObject();

        //fetching Manager
        $entityManager = $args->getObjectManager();

         //checking if entity is a User entity
        if ($entity instanceof User) {

            //if nickname is not null
            // then slugify nickname
            if ($entity->getNickname() !== null) {

                $slug = $this->slugger->slugify($entity->getNickname());
                $entity->setSlug($slug);

            } else {
    
                //slugifying firstname and lastname
                $fullname = $entity->getFullName();
                $slug = $this->slugger->slugify($fullname);
                $entity->setSlug($slug);
            }

            $entityManager->flush();
            
        }else{

            //slugify
            $slug = $this->slugger->slugify($entity->getTitle());
            $entity->setSlug($slug->toString());
    
            $entityManager->flush();
        }


    }
}
